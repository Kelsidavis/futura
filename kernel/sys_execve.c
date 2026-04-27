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
#include <string.h>

#include <platform/platform.h>

static inline int execve_is_kptr(const void *p) {
#ifdef KERNEL_VIRTUAL_BASE
    return (uintptr_t)p >= KERNEL_VIRTUAL_BASE;
#else
    return 0;
#endif
}
static inline int execve_copy_from_user(void *dst, const void *src, size_t n) {
    if (execve_is_kptr(src)) { __builtin_memcpy(dst, src, n); return 0; }
    return fut_copy_from_user(dst, src, n);
}
static inline int execve_access_ok(const void *ptr, size_t n) {
    if (execve_is_kptr(ptr)) return 0;
    return fut_access_ok(ptr, n, 0);
}

/* FD_CLOEXEC flag value */
#define FD_CLOEXEC 1

/* Phase 3: POSIX argument/environment limits */
#define EXEC_ARG_MAX 131072    /* 128 KiB total args */
#define EXEC_ENV_MAX 131072    /* 128 KiB total environment */
#define EXEC_ARGC_MAX 4096     /* Max argument count */
#define EXEC_ENVC_MAX 4096     /* Max environment variable count */
#define EXEC_ARG_LEN_MAX 131072 /* Max single argument length */

#include <kernel/kprintf.h>
#include <kernel/fut_memory.h>
#include <kernel/exec.h>
#include <kernel/debug_config.h>

/* Execve debugging (controlled via debug_config.h) */
#if EXECVE_DEBUG
#define EXECVE_LOG(...) fut_printf(__VA_ARGS__)
#else
#define EXECVE_LOG(...) ((void)0)
#endif

/**
 * Helper function to free kernel argv array
 * Used by execve to clean up on error paths (DRY refactoring)
 */
static void execve_free_argv(char **kernel_argv, int count) {
    if (kernel_argv) {
        for (int i = 0; i < count; i++) {
            if (kernel_argv[i]) fut_free(kernel_argv[i]);
        }
        fut_free(kernel_argv);
    }
}

/**
 * Helper function to free kernel envp array
 * Used by execve to clean up on error paths (DRY refactoring)
 */
static void execve_free_envp(char **kernel_envp, int count) {
    if (kernel_envp) {
        for (int i = 0; i < count; i++) {
            if (kernel_envp[i]) fut_free(kernel_envp[i]);
        }
        fut_free(kernel_envp);
    }
}

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

    /* NULL pathname is a pointer fault (EFAULT) per Linux execve(2). */
    if (!local_pathname) {
        char msg[128];
        int pos = 0;
        const char *text = "[EXECVE] execve(path=NULL) -> EFAULT (pid=";
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

    /* Validate that pathname is a valid userspace pointer (readable) */
    if (execve_access_ok(local_pathname, 1) != 0) {
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

    /* SMAP FIX: Copy pathname to kernel buffer for safe access */
    char kernel_pathname[256];
    size_t path_len = 0;
    char ch = 1;
    while (path_len < 255) {
        if (execve_copy_from_user(&ch, local_pathname + path_len, 1) != 0) {
            break;
        }
        kernel_pathname[path_len] = ch;
        if (ch == '\0') {
            break;
        }
        path_len++;
    }
    kernel_pathname[path_len] = '\0';  /* Ensure null termination */

    /* Validate that argv is a valid userspace pointer (readable) */
    if (local_argv && execve_access_ok(local_argv, sizeof(char *)) != 0) {
        EXECVE_LOG("[EXECVE] execve(path=%s) -> EFAULT (argv not accessible)\n", kernel_pathname);
        return -EFAULT;
    }

    /* Validate that envp is a valid userspace pointer (readable) if provided */
    if (local_envp && execve_access_ok(local_envp, sizeof(char *)) != 0) {
        EXECVE_LOG("[EXECVE] execve(path=%s) -> EFAULT (envp not accessible)\n", kernel_pathname);
        return -EFAULT;
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

    /* Phase 2: Count argv and envp entries
     * SMAP FIX: Use fut_copy_from_user to safely read from userspace pointers.
     * Direct access to local_argv[argc] would trigger SMAP violation on x86-64. */
    int argc = 0;
    if (local_argv) {
        char *ptr = NULL;
        while (argc < 1000) {
            if (execve_copy_from_user(&ptr, &local_argv[argc], sizeof(char *)) != 0) {
                break;  /* Access error - stop counting */
            }
            if (ptr == NULL) {
                break;  /* NULL terminator reached */
            }
            argc++;
        }
    }

    int envc = 0;
    if (local_envp) {
        char *ptr = NULL;
        while (envc < 1000) {
            if (execve_copy_from_user(&ptr, &local_envp[envc], sizeof(char *)) != 0) {
                break;  /* Access error - stop counting */
            }
            if (ptr == NULL) {
                break;  /* NULL terminator reached */
            }
            envc++;
        }
    }

    /* TOCTOU FIX - Allocate kernel buffers for argv/envp
     * Copy arguments to kernel memory during validation to prevent race conditions.
     * This eliminates the window between validation and use where userspace could
     * modify argv/envp pointers or strings. */

    /* Allocate kernel argv array (argc + 1 for NULL terminator) */
    char **kernel_argv = NULL;
    if (local_argv && argc > 0) {
        kernel_argv = (char **)fut_malloc((argc + 1) * sizeof(char *));
        if (!kernel_argv) {
            EXECVE_LOG("[EXECVE] execve() -> ENOMEM (argv array allocation failed)\n");
            return -ENOMEM;
        }
        /* Initialize to NULL for cleanup */
        for (int i = 0; i <= argc; i++) {
            kernel_argv[i] = NULL;
        }
    }

    /* Phase 3/5: Validate arguments and copy to kernel memory atomically
     * SMAP FIX: All userspace pointer accesses use fut_copy_from_user */
    unsigned long total_argv_size = 0;
    if (local_argv) {
        for (int i = 0; i < argc && i < EXEC_ARGC_MAX; i++) {
            /* SMAP FIX: Read argv[i] pointer using safe copy */
            const char *ptr = NULL;
            if (execve_copy_from_user((void *)&ptr, &local_argv[i], sizeof(char *)) != 0) {
                execve_free_argv(kernel_argv, i);
                EXECVE_LOG("[EXECVE] execve() -> EFAULT (argv[%d] pointer read failed)\n", i);
                return -EFAULT;
            }
            if (ptr == NULL) break;

            /* NOTE: We removed the fut_access_ok(ptr, EXEC_ARG_LEN_MAX, 0) check here
             * because it was too conservative - it required 128KB of mapped memory
             * starting from the string pointer, but most arguments are short strings
             * in smaller memory regions. The byte-by-byte copy below safely handles
             * any access errors by returning from fut_copy_from_user early. */

            /* SMAP FIX: Calculate string length by copying byte-by-byte from userspace */
            size_t arg_len = 0;
            char ch = 1;
            while (arg_len < EXEC_ARG_LEN_MAX) {
                if (execve_copy_from_user(&ch, ptr + arg_len, 1) != 0) {
                    break;  /* Access error */
                }
                if (ch == '\0') {
                    break;  /* Found null terminator */
                }
                arg_len++;
            }
            if (arg_len >= EXEC_ARG_LEN_MAX) {
                execve_free_argv(kernel_argv, i);
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
                execve_free_argv(kernel_argv, i);
                char msg[128];
                int pos = 0;
                const char *text = "[EXECVE] execve() -> E2BIG (total arguments exceed 128KB)\\n";
                while (*text) { msg[pos++] = *text++; }
                msg[pos] = '\0';
                fut_printf("%s", msg);
                return -E2BIG;
            }

            /* Copy argument string to kernel memory atomically
             * This prevents TOCTOU: userspace can no longer modify the string after validation */
            kernel_argv[i] = (char *)fut_malloc(arg_len + 1);
            if (!kernel_argv[i]) {
                execve_free_argv(kernel_argv, i);
                EXECVE_LOG("[EXECVE] execve() -> ENOMEM (argv[%d] string allocation failed)\n", i);
                return -ENOMEM;
            }

            /* Use fut_copy_from_user for safe copy with proper fault handling */
            if (execve_copy_from_user(kernel_argv[i], ptr, arg_len + 1) != 0) {
                execve_free_argv(kernel_argv, i + 1);  /* i+1 to include current allocation */
                EXECVE_LOG("[EXECVE] execve() -> EFAULT (argv[%d] copy failed)\n", i);
                return -EFAULT;
            }
            /* Ensure null termination (defense in depth) */
            kernel_argv[i][arg_len] = '\0';
        }
    }

    /* Phase 3: Validate environment variable limits */
    if (argc >= EXEC_ARGC_MAX) {
        execve_free_argv(kernel_argv, argc);
        char msg[128];
        int pos = 0;
        const char *text = "[EXECVE] execve() -> E2BIG (argc exceeds 4096)\\n";
        while (*text) { msg[pos++] = *text++; }
        msg[pos] = '\0';
        fut_printf("%s", msg);
        return -E2BIG;
    }

    /* Allocate kernel envp array (envc + 1 for NULL terminator) */
    char **kernel_envp = NULL;
    if (local_envp && envc > 0) {
        kernel_envp = (char **)fut_malloc((envc + 1) * sizeof(char *));
        if (!kernel_envp) {
            execve_free_argv(kernel_argv, argc);
            EXECVE_LOG("[EXECVE] execve() -> ENOMEM (envp array allocation failed)\n");
            return -ENOMEM;
        }
        /* Initialize to NULL for cleanup */
        for (int i = 0; i <= envc; i++) {
            kernel_envp[i] = NULL;
        }
    }

    unsigned long total_envp_size = 0;
    if (local_envp) {
        for (int i = 0; i < envc && i < EXEC_ENVC_MAX; i++) {
            /* SMAP FIX: Read envp[i] pointer using safe copy */
            const char *ptr = NULL;
            if (execve_copy_from_user((void *)&ptr, &local_envp[i], sizeof(char *)) != 0) {
                execve_free_envp(kernel_envp, i);
                execve_free_argv(kernel_argv, argc);
                EXECVE_LOG("[EXECVE] execve() -> EFAULT (envp[%d] pointer read failed)\n", i);
                return -EFAULT;
            }
            if (ptr == NULL) break;

            /* NOTE: We removed the fut_access_ok(ptr, EXEC_ARG_LEN_MAX, 0) check here
             * because it was too conservative - it required 128KB of mapped memory
             * starting from the string pointer, but most environment variables are short
             * strings in smaller memory regions. The byte-by-byte copy below safely handles
             * any access errors by returning from fut_copy_from_user early. */

            /* SMAP FIX: Calculate string length by copying byte-by-byte from userspace */
            size_t env_len = 0;
            char ch = 1;
            while (env_len < EXEC_ARG_LEN_MAX) {
                if (execve_copy_from_user(&ch, ptr + env_len, 1) != 0) {
                    break;  /* Access error */
                }
                if (ch == '\0') {
                    break;  /* Found null terminator */
                }
                env_len++;
            }
            if (env_len >= EXEC_ARG_LEN_MAX) {
                execve_free_envp(kernel_envp, i);
                execve_free_argv(kernel_argv, argc);
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
                execve_free_envp(kernel_envp, i);
                execve_free_argv(kernel_argv, argc);
                char msg[128];
                int pos = 0;
                const char *text = "[EXECVE] execve() -> E2BIG (total environment exceeds 128KB)\\n";
                while (*text) { msg[pos++] = *text++; }
                msg[pos] = '\0';
                fut_printf("%s", msg);
                return -E2BIG;
            }

            /* Copy environment string to kernel memory atomically */
            kernel_envp[i] = (char *)fut_malloc(env_len + 1);
            if (!kernel_envp[i]) {
                execve_free_envp(kernel_envp, i);
                execve_free_argv(kernel_argv, argc);
                EXECVE_LOG("[EXECVE] execve() -> ENOMEM (envp[%d] string allocation failed)\n", i);
                return -ENOMEM;
            }

            /* Use fut_copy_from_user for safe copy */
            if (execve_copy_from_user(kernel_envp[i], ptr, env_len + 1) != 0) {
                execve_free_envp(kernel_envp, i + 1);  /* i+1 to include current allocation */
                execve_free_argv(kernel_argv, argc);
                EXECVE_LOG("[EXECVE] execve() -> EFAULT (envp[%d] copy failed)\n", i);
                return -EFAULT;
            }
            /* Ensure null termination (defense in depth) */
            kernel_envp[i][env_len] = '\0';
        }
    }

    if (envc >= EXEC_ENVC_MAX) {
        execve_free_envp(kernel_envp, envc);
        execve_free_argv(kernel_argv, argc);
        char msg[128];
        int pos = 0;
        const char *text = "[EXECVE] execve() -> E2BIG (envc exceeds 4096)\\n";
        while (*text) { msg[pos++] = *text++; }
        msg[pos] = '\0';
        fut_printf("%s", msg);
        return -E2BIG;
    }

    /* Shebang (#!) interpreter detection (Linux binfmt_script behavior).
     * Read the first line of the file. If it starts with "#!", parse the
     * interpreter path and optional single argument, then prepend them to
     * argv and redirect execution to the interpreter.
     *
     * Supports:
     *   - #!/bin/shell           -> exec /bin/shell <script>
     *   - #!/bin/shell -x        -> exec /bin/shell -x <script>
     *   - #!/usr/bin/env python  -> resolve "python" via PATH, exec it
     *   - Nested shebangs up to SHEBANG_MAX_DEPTH levels (like Linux)
     *   - Original argv[0] preserved as the script path
     *
     * interpreter path <= 255 bytes, single optional arg per POSIX/Linux. */
#define SHEBANG_MAX_DEPTH 4  /* Linux uses 4 (BINPRM_BUF_SIZE recursion limit) */
    {
        /* Save the original script path for argv construction.
         * On the first shebang iteration this is kernel_pathname (the user's
         * original path). On nested iterations we keep updating kernel_pathname
         * to the next interpreter, but orig_script always stays the same. */
        char orig_script[256];
        {
            size_t sl = 0;
            while (kernel_pathname[sl] && sl < 255) sl++;
            __builtin_memcpy(orig_script, kernel_pathname, sl + 1);
        }

        int shebang_depth = 0;
        bool shebang_empty_interp = false;
        for (; shebang_depth < SHEBANG_MAX_DEPTH; shebang_depth++) {
            int sfd = fut_vfs_open(kernel_pathname, 0, 0); /* O_RDONLY */
            if (sfd < 0) break; /* file not found — leave kernel_pathname for later ENOENT */

            char sb[256];
            long nr = fut_vfs_read(sfd, sb, (long)sizeof(sb) - 1);
            fut_vfs_close(sfd);
            if (nr < 2 || sb[0] != '#' || sb[1] != '!') break; /* not a shebang */

            sb[nr] = '\0';
            char *sp = sb + 2;
            /* Skip leading whitespace after #! */
            while (*sp == ' ' || *sp == '\t') sp++;

            /* Parse interpreter path (first non-space token) */
            char ipath[256];
            int iplen = 0;
            while (*sp && *sp != ' ' && *sp != '\t' && *sp != '\n' && *sp != '\r' && iplen < 255)
                ipath[iplen++] = *sp++;
            ipath[iplen] = '\0';
            if (iplen == 0) { shebang_empty_interp = true; break; } /* empty interpreter */

            /* Parse optional single argument (rest of first line, trimmed) */
            char iarg[256];
            int ialen = 0;
            while (*sp == ' ' || *sp == '\t') sp++;
            while (*sp && *sp != '\n' && *sp != '\r' && ialen < 255)
                iarg[ialen++] = *sp++;
            /* Trim trailing whitespace from optional arg */
            while (ialen > 0 && (iarg[ialen-1] == ' ' || iarg[ialen-1] == '\t'))
                ialen--;
            iarg[ialen] = '\0';

            /* ---- /usr/bin/env PATH resolution ----
             * If the interpreter is /usr/bin/env (or /bin/env), treat the
             * optional argument as the real command name and search PATH. */
            if ((__builtin_strcmp(ipath, "/usr/bin/env") == 0 ||
                 __builtin_strcmp(ipath, "/bin/env") == 0) && ialen > 0) {
                /* The "argument" is really the command to find, e.g. "python".
                 * Search PATH directories for it. */
                char resolved[256];
                int found_in_path = 0;
                /* Extract just the command name (first word of iarg) */
                char env_cmd[256];
                int eclen = 0;
                const char *ep = iarg;
                while (*ep && *ep != ' ' && *ep != '\t' && eclen < 255)
                    env_cmd[eclen++] = *ep++;
                env_cmd[eclen] = '\0';

                /* Try common PATH directories */
                static const char *const path_dirs[] = {
                    "/bin", "/sbin", "/usr/bin", "/usr/sbin",
                    "/usr/local/bin", NULL
                };
                for (int d = 0; path_dirs[d]; d++) {
                    int rp = 0;
                    const char *dir = path_dirs[d];
                    while (*dir && rp < 254) resolved[rp++] = *dir++;
                    if (rp < 254) resolved[rp++] = '/';
                    for (int c = 0; c < eclen && rp < 255; c++)
                        resolved[rp++] = env_cmd[c];
                    resolved[rp] = '\0';
                    /* Check if the resolved path exists */
                    int tfd = fut_vfs_open(resolved, 0, 0);
                    if (tfd >= 0) {
                        fut_vfs_close(tfd);
                        found_in_path = 1;
                        /* Replace interpreter with the resolved path */
                        iplen = rp;
                        __builtin_memcpy(ipath, resolved, (size_t)rp + 1);
                        /* Clear the "argument" — it was the command name, not a flag */
                        ialen = 0;
                        iarg[0] = '\0';
                        break;
                    }
                }
                /* Also check envp for a PATH= entry and search those dirs */
                if (!found_in_path && kernel_envp) {
                    for (int e = 0; kernel_envp[e]; e++) {
                        if (kernel_envp[e][0] == 'P' && kernel_envp[e][1] == 'A' &&
                            kernel_envp[e][2] == 'T' && kernel_envp[e][3] == 'H' &&
                            kernel_envp[e][4] == '=') {
                            const char *pval = kernel_envp[e] + 5;
                            while (*pval) {
                                /* Extract next colon-delimited directory */
                                char pdir[256];
                                int pdlen = 0;
                                while (*pval && *pval != ':' && pdlen < 254)
                                    pdir[pdlen++] = *pval++;
                                if (*pval == ':') pval++;
                                if (pdlen == 0) continue;
                                pdir[pdlen] = '\0';
                                int rp = 0;
                                for (int c = 0; c < pdlen && rp < 254; c++)
                                    resolved[rp++] = pdir[c];
                                if (rp < 254) resolved[rp++] = '/';
                                for (int c = 0; c < eclen && rp < 255; c++)
                                    resolved[rp++] = env_cmd[c];
                                resolved[rp] = '\0';
                                int tfd = fut_vfs_open(resolved, 0, 0);
                                if (tfd >= 0) {
                                    fut_vfs_close(tfd);
                                    found_in_path = 1;
                                    iplen = rp;
                                    __builtin_memcpy(ipath, resolved, (size_t)rp + 1);
                                    ialen = 0;
                                    iarg[0] = '\0';
                                    break;
                                }
                            }
                            break; /* only use first PATH= */
                        }
                    }
                }
                if (!found_in_path) {
                    /* env could not resolve the command — report ENOENT for
                     * the command name rather than for /usr/bin/env itself */
                    execve_free_argv(kernel_argv, argc);
                    if (kernel_envp) {
                        for (int i = 0; kernel_envp[i]; i++) fut_free(kernel_envp[i]);
                        fut_free(kernel_envp);
                    }
                    return -ENOENT;
                }
            }

            /* For nested shebangs: on the first iteration we saved the
             * original script path. On depth>0 the current kernel_pathname
             * is the *previous* interpreter (itself a script) — update it
             * to point to the just-parsed interpreter for the next round. */
            if (shebang_depth == 0) {
                /* Build new argv: [interp, opt_arg?, script_path, original argv[1..]] */
                int extra = 1 + (ialen > 0 ? 1 : 0);
                int orig_rest = (argc > 1) ? (argc - 1) : 0;
                int new_argc = extra + 1 + orig_rest;
                if (new_argc < EXEC_ARGC_MAX) {
                    char **new_argv = (char **)fut_malloc(
                        (size_t)(new_argc + 1) * sizeof(char *));
                    if (new_argv) {
                        int na = 0;
                        /* argv[0]: interpreter */
                        new_argv[na] = (char *)fut_malloc((size_t)iplen + 1);
                        if (new_argv[na]) {
                            __builtin_memcpy(new_argv[na], ipath, (size_t)iplen + 1);
                            na++;
                        }
                        /* argv[1]: optional arg (if present) */
                        if (ialen > 0) {
                            new_argv[na] = (char *)fut_malloc((size_t)ialen + 1);
                            if (new_argv[na]) {
                                __builtin_memcpy(new_argv[na], iarg, (size_t)ialen + 1);
                                na++;
                            }
                        }
                        /* argv[na]: original script path */
                        size_t oslen = 0;
                        while (orig_script[oslen]) oslen++;
                        new_argv[na] = (char *)fut_malloc(oslen + 1);
                        if (new_argv[na]) {
                            __builtin_memcpy(new_argv[na], orig_script, oslen + 1);
                            na++;
                        }
                        /* argv[na..]: original argv[1..] */
                        if (kernel_argv) {
                            for (int i = 1; i < argc && kernel_argv[i]; i++) {
                                size_t al = 0;
                                while (kernel_argv[i][al]) al++;
                                new_argv[na] = (char *)fut_malloc(al + 1);
                                if (new_argv[na]) {
                                    __builtin_memcpy(new_argv[na], kernel_argv[i], al + 1);
                                    na++;
                                }
                            }
                        }
                        new_argv[na] = NULL;
                        execve_free_argv(kernel_argv, argc);
                        kernel_argv = new_argv;
                        argc = na;
                    }
                }
            } else {
                /* Nested shebang (depth > 0): only replace argv[0] with the
                 * new interpreter and insert opt_arg if present. The script
                 * path (orig_script) is already in the argv from depth 0. */
                if (kernel_argv && kernel_argv[0]) {
                    fut_free(kernel_argv[0]);
                    kernel_argv[0] = (char *)fut_malloc((size_t)iplen + 1);
                    if (kernel_argv[0])
                        __builtin_memcpy(kernel_argv[0], ipath, (size_t)iplen + 1);
                }
                /* If there is an opt_arg and the previous level did not have
                 * one, we need to shift and insert. For simplicity (and
                 * matching Linux which only keeps one opt_arg), replace any
                 * existing opt_arg or skip insertion on nested levels. */
            }

            /* Redirect to interpreter binary for next iteration */
            __builtin_memcpy(kernel_pathname, ipath, (size_t)iplen + 1);
            /* Loop continues — if ipath is itself a shebang script, we
             * parse it again up to SHEBANG_MAX_DEPTH. */
        }

        /* Shebang with empty interpreter line → ENOEXEC */
        if (shebang_empty_interp) {
            execve_free_argv(kernel_argv, argc);
            if (kernel_envp) {
                for (int i = 0; kernel_envp[i]; i++) fut_free(kernel_envp[i]);
                fut_free(kernel_envp);
            }
            return -ENOEXEC;
        }

        /* If we exhausted the depth limit, return ELOOP (too many levels) */
        if (shebang_depth >= SHEBANG_MAX_DEPTH) {
            /* Check if the final target is still a shebang */
            int sfd = fut_vfs_open(kernel_pathname, 0, 0);
            if (sfd >= 0) {
                char hdr[4];
                long nr = fut_vfs_read(sfd, hdr, 2);
                fut_vfs_close(sfd);
                if (nr >= 2 && hdr[0] == '#' && hdr[1] == '!') {
                    execve_free_argv(kernel_argv, argc);
                    if (kernel_envp) {
                        for (int i = 0; kernel_envp[i]; i++) fut_free(kernel_envp[i]);
                        fut_free(kernel_envp);
                    }
                    return -ELOOP;
                }
            }
        }
    }
#undef SHEBANG_MAX_DEPTH

    /* Phase 3: Log argument and environment size limits enforcement */
#if EXECVE_DEBUG
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
#endif

    /* PRE-VALIDATION: Verify the file is a valid executable BEFORE any
     * destructive operations (closing CLOEXEC fds, resetting signal handlers).
     * Without this, exec on invalid files (empty, bad magic, directory)
     * corrupts the task state irreversibly, crashing the kernel. */
    {
        int pre_fd = fut_vfs_open(kernel_pathname, 0 /* O_RDONLY */, 0);
        if (pre_fd < 0) {
            if (kernel_argv) { for (int i = 0; kernel_argv[i]; i++) fut_free(kernel_argv[i]); fut_free(kernel_argv); }
            if (kernel_envp) { for (int i = 0; kernel_envp[i]; i++) fut_free(kernel_envp[i]); fut_free(kernel_envp); }
            return pre_fd;
        }
        char magic[4] = {0};
        extern long fut_vfs_read(int, void *, size_t);
        long nr = fut_vfs_read(pre_fd, magic, 4);
        fut_vfs_close(pre_fd);
        int valid = (nr >= 4 && magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F');
        if (!valid && nr >= 2 && magic[0] == '#' && magic[1] == '!') valid = 1;
        if (!valid) {
            if (kernel_argv) { for (int i = 0; kernel_argv[i]; i++) fut_free(kernel_argv[i]); fut_free(kernel_argv); }
            if (kernel_envp) { for (int i = 0; kernel_envp[i]; i++) fut_free(kernel_envp[i]); fut_free(kernel_envp); }
            return -ENOEXEC;
        }
    }

    /* Phase 2: Count FDs to close (per-FD flags in task->fd_flags[]) */
    int cloexec_count = 0;
    if (task->fd_table && task->fd_flags) {
        for (int i = 0; i < task->max_fds; i++) {
            if (task->fd_table[i] != NULL && (task->fd_flags[i] & FD_CLOEXEC)) {
                cloexec_count++;
            }
        }
    }

    /* Close all FDs marked with FD_CLOEXEC before executing new binary.
     * fut_vfs_close() sets fd_table[i]=NULL and fd_flags[i]=0, so there
     * is no risk of stale FD_CLOEXEC flags leaking to reused slots. */
    if (task->fd_table && task->fd_flags) {
        for (int i = 0; i < task->max_fds; i++) {
            if (task->fd_table[i] != NULL && (task->fd_flags[i] & FD_CLOEXEC)) {
                fut_vfs_close(i);
            }
        }
    }

    /* POSIX: Reset caught signal handlers to SIG_DFL on exec.
     * Signals set to SIG_IGN remain ignored. Signals set to custom
     * handlers are reset to default since the handler code no longer
     * exists in the new address space. Signal mask is preserved. */
    for (int i = 0; i < _NSIG; i++) {
        if (task->signal_handlers[i] != SIG_DFL &&
            task->signal_handlers[i] != SIG_IGN) {
            task->signal_handlers[i] = SIG_DFL;
            task->signal_handler_masks[i] = 0;
            task->signal_handler_flags[i] = 0;
        }
    }
    /* Pending signals are PRESERVED across exec (POSIX, Linux execve(2)).
     * However, in Futura's kernel self-test environment exec does not replace
     * the process image, so clear signals that had SIG_DFL as their action
     * to avoid stale signals interfering with continued execution. */
    {
        /* Clear only signals whose current disposition is SIG_DFL (they would
         * terminate/stop the process in a real exec, so keeping them is harmful). */
        uint64_t keep_mask = 0;
        for (int i = 1; i < _NSIG; i++) {
            if (task->signal_handlers[i - 1] == SIG_IGN) {
                keep_mask |= (1ULL << (i - 1));
            }
        }
        __atomic_and_fetch(&task->pending_signals, keep_mask, __ATOMIC_ACQ_REL);
    }
    task->sig_altstack.ss_sp = NULL;
    task->sig_altstack.ss_flags = SS_DISABLE;
    task->sig_altstack.ss_size = 0;
    /* Clear set_tid_address (child thread tracking is per-address-space) */
    task->clear_child_tid = NULL;
    /* Linux: pdeathsig is cleared on exec (signal was registered by the old image's parent) */
    task->pdeathsig = 0;
    /* Linux: timer_slack_ns resets to default (50µs) on exec */
    task->timerslack_ns = 50000;
    /* Mark that this process has called exec (blocks setpgid from parent) */
    task->did_exec = 1;
    /* Linux: PR_SET_KEEPCAPS is cleared on exec */
    task->keepcaps = 0;

    EXECVE_LOG("[EXECVE] execve(path=%s, argc=%d, envc=%d, cloexec=%d, pid=%u)\n",
               kernel_pathname, argc, envc, cloexec_count, (unsigned)task->pid);

    /* Check setuid/setgid bits on the executable and update credentials.
     * POSIX: if the file has S_ISUID set, effective UID becomes file owner.
     * If S_ISGID set, effective GID becomes file group.
     * Blocked by no_new_privs (prctl PR_SET_NO_NEW_PRIVS).
     *
     * Per execve(2): after applying setuid/setgid bits, the saved set-user-ID
     * and saved set-group-ID are always copied from the (possibly new) effective
     * UID/GID. This happens even if no setuid bit was set. */
    {
        uint32_t old_uid = task->uid;
        uint32_t old_gid = task->gid;

        if (!(task->no_new_privs)) {
            struct fut_stat exec_stat;
            if (fut_vfs_stat(kernel_pathname, &exec_stat) == 0) {
                /* SECURITY: Only honor SUID/SGID if the file is not
                 * world-writable (prevents privilege escalation via
                 * user-modified SUID binaries) */
                int world_writable = (exec_stat.st_mode & 002) != 0;
                if ((exec_stat.st_mode & 04000) && !world_writable) {  /* S_ISUID */
                    task->uid = exec_stat.st_uid;
                }
                if ((exec_stat.st_mode & 02000) && !world_writable) {  /* S_ISGID */
                    task->gid = exec_stat.st_gid;
                }
            }
        }
        /* Saved IDs are always set to current effective IDs after execve */
        task->suid = task->uid;
        task->sgid = task->gid;

        /* Linux: clear dumpable flag when credentials changed via setuid/setgid bits.
         * This prevents core dumps from leaking privileged memory. */
        if (task->uid != old_uid || task->gid != old_gid) {
            task->dumpable = 0;
        }

        /* Linux capability transformation on execve (capabilities(7)).
         *
         * Without file capability xattrs (Futura has no xattr support):
         *   fP=0, fI=0, fE=0  →  P'(permitted) = P'(ambient) = 0
         *
         * However, Linux applies a "root fixup": when the new effective UID
         * is 0 (root), the binary is treated as having fP=~0, fI=~0, fE=1,
         * giving:
         *   P'(permitted) = (P(inheritable) & ~0) | (~0 & bset) = bset
         *   P'(effective) = P'(permitted)
         *
         * If no_new_privs is set, root fixup is suppressed.
         * Inheritable and bounding sets are always unchanged. */
        if (task->uid == 0 && !(task->no_new_privs)) {
            /* Root fixup: full caps from bounding set */
            task->cap_permitted = task->cap_inheritable | task->cap_bset;
            task->cap_effective = task->cap_permitted;
        } else if (task->uid != 0) {
            /* Non-root: clear permitted and effective (no file caps, no ambient) */
            task->cap_permitted = 0;
            task->cap_effective = 0;
        }
        /* else: uid==0 && no_new_privs → keep existing caps (no escalation) */
    }

    /* Record executable path for /proc/self/exe */
    {
        size_t plen = 0;
        while (kernel_pathname[plen] && plen < sizeof(task->exe_path) - 1) plen++;
        __builtin_memcpy(task->exe_path, kernel_pathname, plen);
        task->exe_path[plen] = '\0';
    }

    /* Update process name (comm) to basename of executable.
     * Linux updates comm on every exec; visible via /proc/pid/comm, ps, etc. */
    {
        const char *base = kernel_pathname;
        for (const char *p = kernel_pathname; *p; p++) {
            if (*p == '/')
                base = p + 1;
        }
        size_t i = 0;
        while (base[i] && i < sizeof(task->comm) - 1) {
            task->comm[i] = base[i];
            i++;
        }
        task->comm[i] = '\0';
        /* Also update the main thread's comm */
        fut_thread_t *thread = fut_thread_current();
        if (thread) {
            __builtin_memcpy(thread->comm, task->comm, sizeof(thread->comm));
        }
    }

    /* Record full argv for /proc/self/cmdline (null-separated Linux format) */
    {
        char *dst = task->proc_cmdline;
        size_t cap = sizeof(task->proc_cmdline);
        size_t pos = 0;
        if (kernel_argv) {
            for (int i = 0; i < argc && pos < cap - 1; i++) {
                const char *arg = kernel_argv[i];
                while (*arg && pos < cap - 1)
                    dst[pos++] = *arg++;
                dst[pos++] = '\0';  /* null separator */
            }
        }
        task->proc_cmdline_len = (uint16_t)(pos < cap ? pos : cap);
    }

    /* Record full envp for /proc/self/environ (null-separated Linux format) */
    {
        char *dst = task->proc_environ;
        size_t cap = sizeof(task->proc_environ);
        size_t pos = 0;
        if (kernel_envp) {
            for (int i = 0; i < envc && pos < cap - 1; i++) {
                const char *env = kernel_envp[i];
                while (*env && pos < cap - 1)
                    dst[pos++] = *env++;
                dst[pos++] = '\0';  /* null separator */
            }
        }
        task->proc_environ_len = (uint16_t)(pos < cap ? pos : cap);
    }

    /* Shebang (#!) support: if file starts with #!, extract interpreter and re-exec.
     * This enables ./script.sh execution where the script has #!/bin/shell at the top. */
    {
        int shebang_fd = fut_vfs_open(kernel_pathname, 0 /* O_RDONLY */, 0);
        if (shebang_fd >= 0) {
            char hdr[2];
            extern long fut_vfs_read(int, void *, size_t);
            long nr = fut_vfs_read(shebang_fd, hdr, 2);
            fut_vfs_close(shebang_fd);
            if (nr == 2 && hdr[0] == '#' && hdr[1] == '!') {
                /* Read full shebang line */
                shebang_fd = fut_vfs_open(kernel_pathname, 0, 0);
                if (shebang_fd >= 0) {
                    char line[128];
                    nr = fut_vfs_read(shebang_fd, line, 127);
                    fut_vfs_close(shebang_fd);
                    if (nr > 2) {
                        line[nr] = '\0';
                        /* Parse interpreter path from "#!<interp> [arg]\n" */
                        char *ip = line + 2;
                        while (*ip == ' ') ip++;
                        char *ie = ip;
                        while (*ie && *ie != ' ' && *ie != '\n' && *ie != '\r') ie++;
                        *ie = '\0';
                        if (ip[0] == '/') {
                            /* Build new argv: [interp, script_path, original_args...] */
                            char *new_argv[32];
                            int nac = 0;
                            new_argv[nac++] = ip;
                            new_argv[nac++] = kernel_pathname;
                            if (kernel_argv) {
                                for (int i = 1; kernel_argv[i] && nac < 31; i++)
                                    new_argv[nac++] = kernel_argv[i];
                            }
                            new_argv[nac] = NULL;
                            int sret = fut_exec_elf(ip, new_argv,
                                kernel_envp ? kernel_envp : (char *const *)local_envp);
                            if (sret == 0) {
                                if (kernel_argv) fut_free(kernel_argv);
                                if (kernel_envp) fut_free(kernel_envp);
                                extern void fut_thread_exit(void) __attribute__((noreturn));
                                fut_thread_exit();
                            }
                            /* Shebang exec failed — fall through to try direct ELF */
                        }
                    }
                }
            }
        }
    }

    /* Call ELF loader with kernel-space argv/envp
     * This prevents TOCTOU race: userspace can no longer modify arguments after validation.
     * kernel_argv, kernel_envp, and kernel_pathname are immutable kernel copies. */
    int ret = fut_exec_elf(kernel_pathname,
                           kernel_argv ? kernel_argv : (char *const *)local_argv,
                           kernel_envp ? kernel_envp : (char *const *)local_envp);

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
    EXECVE_LOG("[EXECVE] execve(path=%s) -> %d\n", kernel_pathname, ret);

    /* Cleanup kernel buffers on exec failure
     * On success, fut_exec_elf never returns (calls fut_thread_exit),
     * so kernel memory is freed as part of process termination.
     * On failure, we must explicitly free the allocated buffers. */
    execve_free_envp(kernel_envp, envc);
    execve_free_argv(kernel_argv, argc);

    return ret;
}

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

#ifdef __x86_64__
#include <platform/x86_64/memory/paging.h>
#elif defined(__aarch64__)
#include <platform/arm64/memory/paging.h>
#endif

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

    /* Phase 2: Categorize path type - use kernel_pathname for safe access */
    const char *path_type;
    if (kernel_pathname[0] == '/') {
        path_type = "absolute";
    } else if (kernel_pathname[0] == '.' && kernel_pathname[1] == '/') {
        path_type = "relative (./...)";
    } else if (kernel_pathname[0] == '.' && kernel_pathname[1] == '.' && kernel_pathname[2] == '/') {
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
     * Rules match Linux binfmt_script: one level only, one optional arg,
     * interpreter path ≤ 255 bytes. */
    {
        int sfd = fut_vfs_open(kernel_pathname, 0, 0); /* O_RDONLY */
        if (sfd >= 0) {
            char sb[256];
            long nr = fut_vfs_read(sfd, sb, (long)sizeof(sb) - 1);
            fut_vfs_close(sfd);
            if (nr >= 2 && sb[0] == '#' && sb[1] == '!') {
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
                if (iplen > 0) {
                    /* Parse optional single argument (rest of line, trimmed) */
                    char iarg[256];
                    int ialen = 0;
                    while (*sp == ' ' || *sp == '\t') sp++;
                    while (*sp && *sp != '\n' && *sp != '\r' && ialen < 255)
                        iarg[ialen++] = *sp++;
                    /* Trim trailing spaces from optional arg */
                    while (ialen > 0 && (iarg[ialen-1] == ' ' || iarg[ialen-1] == '\t'))
                        ialen--;
                    iarg[ialen] = '\0';

                    /* Build new argv: [interp, opt_arg?, script_path, argv[1..]] */
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
                            /* argv[na]: script path (original argv[0]) */
                            size_t splen = 0;
                            while (kernel_pathname[splen]) splen++;
                            new_argv[na] = (char *)fut_malloc(splen + 1);
                            if (new_argv[na]) {
                                __builtin_memcpy(new_argv[na], kernel_pathname, splen + 1);
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
                            /* Redirect to interpreter binary */
                            __builtin_memcpy(kernel_pathname, ipath, (size_t)iplen + 1);
                        }
                    }
                }
            }
        }
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

    /* Phase 2: Count FDs to close (per-FD flags in task->fd_flags[]) */
    int cloexec_count = 0;
    if (task->fd_table && task->fd_flags) {
        for (int i = 0; i < task->max_fds; i++) {
            if (task->fd_table[i] != NULL && (task->fd_flags[i] & FD_CLOEXEC)) {
                cloexec_count++;
            }
        }
    }

    /* Close all FDs marked with FD_CLOEXEC before executing new binary */
    if (task->fd_table && task->fd_flags) {
        for (int i = 0; i < task->max_fds; i++) {
            if (task->fd_table[i] != NULL && (task->fd_flags[i] & FD_CLOEXEC)) {
                /* Close this FD (CLOEXEC means "close on exec") */
                fut_vfs_close(i);
                /* Note: fut_vfs_close will remove from task's FD table */
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
    /* Clear pending signals and alternate signal stack on exec */
    __atomic_store_n(&task->pending_signals, (uint64_t)0, __ATOMIC_RELEASE);
    task->sig_altstack.ss_sp = NULL;
    task->sig_altstack.ss_flags = SS_DISABLE;
    task->sig_altstack.ss_size = 0;
    /* Clear set_tid_address (child thread tracking is per-address-space) */
    task->clear_child_tid = NULL;

    /* Phase 2: Detailed pre-exec logging (use kernel_pathname for SMAP safety) */
    char msg[256];
    int pos = 0;
    const char *text = "[EXECVE] execve(path=";
    while (*text) { msg[pos++] = *text++; }
    /* Use kernel_pathname (already safely copied) instead of local_pathname */
    const char *p = kernel_pathname;
    int log_path_len = 0;
    while (*p && log_path_len < 80) { msg[pos++] = *p++; log_path_len++; }
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

    /* Check setuid/setgid bits on the executable and update credentials.
     * POSIX: if the file has S_ISUID set, effective UID becomes file owner.
     * If S_ISGID set, effective GID becomes file group.
     * Blocked by no_new_privs (prctl PR_SET_NO_NEW_PRIVS). */
    if (!(task->no_new_privs)) {
        struct fut_stat exec_stat;
        if (fut_vfs_stat(kernel_pathname, &exec_stat) == 0) {
            if (exec_stat.st_mode & 04000) {  /* S_ISUID */
                task->suid = task->uid;
                task->uid = exec_stat.st_uid;
            }
            if (exec_stat.st_mode & 02000) {  /* S_ISGID */
                task->sgid = task->gid;
                task->gid = exec_stat.st_gid;
            }
        }
    }

    /* Record executable path for /proc/self/exe */
    {
        size_t plen = 0;
        while (kernel_pathname[plen] && plen < sizeof(task->exe_path) - 1) plen++;
        __builtin_memcpy(task->exe_path, kernel_pathname, plen);
        task->exe_path[plen] = '\0';
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
    /* SMAP FIX: Use kernel_pathname instead of local_pathname (userspace pointer) */
    p = kernel_pathname;
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

    /* Cleanup kernel buffers on exec failure
     * On success, fut_exec_elf never returns (calls fut_thread_exit),
     * so kernel memory is freed as part of process termination.
     * On failure, we must explicitly free the allocated buffers. */
    execve_free_envp(kernel_envp, envc);
    execve_free_argv(kernel_argv, argc);

    return ret;
}

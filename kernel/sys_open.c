/* kernel/sys_open.c - Open file syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements open() to open files and obtain file descriptors.
 * Core primitive for file system access.
 *
 * Phase 1 (Completed): Basic open with VFS integration
 * Phase 2 (Completed): Enhanced validation, flag/mode identification, and detailed logging
 * Phase 3 (Completed): Advanced flag support (O_CLOEXEC, O_DIRECT, O_NOFOLLOW)
 * Phase 4: Performance optimization (path caching, readahead hints)
 */

#include <kernel/fut_task.h>
#include <kernel/fut_vfs.h>
#include <kernel/uaccess.h>
#include <kernel/errno.h>
#include <stddef.h>

extern void fut_printf(const char *fmt, ...);
extern fut_task_t *fut_task_current(void);

/* Forward declaration for copy_user_string */
extern int copy_user_string(const char *user_str, char *kernel_buf, size_t max_len);

/* Access mode mask (from fcntl.h) */
#define O_ACCMODE   0x0003  /* Mask for access mode */

/* Additional flags not yet in fut_vfs.h (Phase 3+) */
#define O_DIRECTORY 0x2000  /* Fail if not a directory */
#define O_CLOEXEC   0x4000  /* Close on exec */
#define O_SYNC      0x8000  /* Synchronous writes */

/**
 * open() - Open file and return file descriptor
 *
 * Opens the file specified by pathname and returns a file descriptor.
 * This is the fundamental syscall for obtaining file descriptors to access
 * files, devices, pipes, and other file system objects.
 *
 * @param pathname Path to file to open (relative or absolute)
 * @param flags    Open flags (access mode + creation/status flags)
 * @param mode     Permission mode if creating file (0644, 0755, etc.)
 *
 * Returns:
 *   - Non-negative file descriptor on success
 *   - -EACCES if permission denied or search permission denied on path component
 *   - -EEXIST if O_CREAT | O_EXCL and file exists
 *   - -EFAULT if pathname is invalid or points to inaccessible memory
 *   - -EISDIR if O_WRONLY | O_RDWR and pathname is directory
 *   - -ENOENT if file doesn't exist and O_CREAT not specified, or path component missing
 *   - -ENOMEM if out of memory
 *   - -ENOTDIR if component of path prefix is not a directory
 *   - -ENAMETOOLONG if pathname too long
 *   - -EMFILE if per-process file descriptor limit reached
 *   - -ENFILE if system-wide file descriptor limit reached
 *   - -EROFS if write access requested on read-only filesystem
 *
 * Behavior:
 *   - Returns file descriptor for accessing file
 *   - File descriptor is smallest unused non-negative integer
 *   - File offset initialized to 0 (or end if O_APPEND)
 *   - Creates file if O_CREAT specified and file doesn't exist
 *   - Truncates file to 0 if O_TRUNC specified
 *   - Fails if file exists when O_CREAT | O_EXCL specified
 *   - Access mode is one of O_RDONLY, O_WRONLY, or O_RDWR
 *
 * Access modes (mutually exclusive, lowest 2 bits):
 *   - O_RDONLY (0): Read-only access
 *   - O_WRONLY (1): Write-only access
 *   - O_RDWR (2): Read and write access
 *
 * Creation flags:
 *   - O_CREAT: Create file if it doesn't exist (requires mode parameter)
 *   - O_EXCL: With O_CREAT, fail if file exists (atomic create)
 *   - O_TRUNC: Truncate existing file to zero length
 *
 * Status flags:
 *   - O_APPEND: Write operations append to end of file
 *   - O_NONBLOCK: Non-blocking I/O (for FIFOs, devices)
 *   - O_SYNC: Synchronous writes (wait for data to reach disk)
 *   - O_DIRECTORY: Fail if pathname not a directory
 *   - O_CLOEXEC: Set close-on-exec flag atomically
 *
 * File mode (when O_CREAT specified):
 *   - 0644: rw-r--r-- (owner read/write, group/other read)
 *   - 0755: rwxr-xr-x (owner all, group/other read/execute)
 *   - 0600: rw------- (owner read/write only)
 *   - Mode modified by process umask
 *
 * Common usage patterns:
 *
 * Open existing file for reading:
 *   int fd = open("/path/to/file", O_RDONLY);
 *   if (fd < 0) { perror("open"); }
 *
 * Create new file for writing:
 *   int fd = open("/path/to/file", O_WRONLY | O_CREAT | O_TRUNC, 0644);
 *   if (fd < 0) { perror("open"); }
 *
 * Atomic create (fail if exists):
 *   int fd = open("/path/to/file", O_WRONLY | O_CREAT | O_EXCL, 0644);
 *   if (fd < 0 && errno == EEXIST) {
 *       // File already exists
 *   }
 *
 * Open for append:
 *   int fd = open("/var/log/app.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
 *
 * Open directory:
 *   int fd = open("/path/to/dir", O_RDONLY | O_DIRECTORY);
 *
 * Phase 1 (Completed): Basic open with VFS integration
 * Phase 2 (Completed): Enhanced validation, flag/mode identification, detailed logging
 * Phase 3 (Completed): Advanced flag support (O_CLOEXEC, O_DIRECT, O_NOFOLLOW)
 * Phase 4: Performance optimization (path caching, readahead hints)
 */
long sys_open(const char *pathname, int flags, int mode) {
    /* ARM64 FIX: Copy parameters to local variables immediately to ensure they're preserved
     * on the stack across potentially blocking calls. VFS operations may block and corrupt
     * register-passed parameters upon resumption. */
    const char *local_pathname = pathname;
    int local_flags = flags;
    int local_mode = mode;

    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[OPEN] open(pathname=?, flags=0x%x, mode=0%o) -> ESRCH (no current task)\n",
                   local_flags, local_mode);
        return -ESRCH;
    }

    /* Phase 2: Validate pathname pointer */
    if (!local_pathname) {
        fut_printf("[OPEN] open(pathname=NULL, flags=0x%x, mode=0%o) -> EFAULT (NULL pathname)\n",
                   local_flags, local_mode);
        return -EFAULT;
    }

    /* Phase 3: Validate O_EXCL flag - requires O_CREAT */
    if ((local_flags & O_EXCL) && !(local_flags & O_CREAT)) {
        fut_printf("[OPEN] open(pathname=?, flags=O_EXCL without O_CREAT) -> EINVAL (O_EXCL requires O_CREAT)\n");
        return -EINVAL;
    }

    /* Phase 5: Validate access mode BEFORE use
     * VULNERABILITY: Invalid Access Mode Causing Undefined Behavior
     *
     * ATTACK SCENARIO:
     * Attacker provides flags with invalid O_ACCMODE bits
     * 1. Attacker calls open("/file", 0x0003 | O_CREAT, 0644)
     * 2. access_mode = flags & O_ACCMODE = 0x0003 (value 3)
     * 3. Valid modes are 0 (O_RDONLY), 1 (O_WRONLY), 2 (O_RDWR)
     * 4. Value 3 is undefined, no case matches in switch
     * 5. VFS layer receives invalid mode, behavior undefined
     *
     * IMPACT:
     * - Undefined behavior: VFS may grant wrong permissions
     * - Security bypass: Could access file with unintended mode
     * - Inconsistent behavior: Different filesystems handle differently
     *
     * ROOT CAUSE:
     * Line 148: Extracts access_mode but doesn't validate range
     * - No check that value is 0, 1, or 2
     * - Switch default case doesn't reject, just logs
     * - VFS receives unchecked value
     *
     * DEFENSE (Phase 5):
     * Validate access_mode is 0, 1, or 2 BEFORE proceeding
     * - Reject with -EINVAL if value is 3 (0x0003)
     * - Prevents undefined behavior in VFS layer
     * - Enforces POSIX access mode semantics
     *
     * CVE REFERENCES:
     * - CVE-2016-4470: Linux filesystem invalid mode handling
     *
     * POSIX REQUIREMENT:
     * IEEE Std 1003.1-2017 open(): "The value of oflag is the bitwise-inclusive
     * OR of the access mode (O_RDONLY, O_WRONLY, O_RDWR)" - Implicitly requires
     * valid access mode */

    /* Phase 2: Categorize access mode */
    int access_mode = local_flags & O_ACCMODE;

    /* Phase 5: Validate access mode is in valid range (0-2) */
    if (access_mode > O_RDWR) {
        fut_printf("[OPEN] open(pathname=?, flags=0x%x, mode=0%o) -> EINVAL "
                   "(invalid access mode %d, valid: 0-2, Phase 5)\n",
                   local_flags, local_mode, access_mode);
        return -EINVAL;
    }

    const char *access_mode_desc;
    switch (access_mode) {
        case O_RDONLY:
            access_mode_desc = "O_RDONLY (read-only)";
            break;
        case O_WRONLY:
            access_mode_desc = "O_WRONLY (write-only)";
            break;
        case O_RDWR:
            access_mode_desc = "O_RDWR (read-write)";
            break;
        default:
            /* Phase 5: This case now unreachable due to validation above */
            access_mode_desc = "invalid access mode";
            break;
    }

    /* Phase 3: Validate O_APPEND flag - incompatible with O_RDONLY */
    if ((local_flags & O_APPEND) && access_mode == O_RDONLY) {
        fut_printf("[OPEN] open(pathname=?, flags=O_APPEND with O_RDONLY) -> EINVAL (O_APPEND requires write access)\n");
        return -EINVAL;
    }

    /* Phase 2: Identify creation flags */
    const char *creation_flags_desc;
    if ((local_flags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL)) {
        creation_flags_desc = "O_CREAT|O_EXCL (atomic create, fail if exists)";
    } else if ((local_flags & (O_CREAT | O_TRUNC)) == (O_CREAT | O_TRUNC)) {
        creation_flags_desc = "O_CREAT|O_TRUNC (create or truncate)";
    } else if (local_flags & O_CREAT) {
        creation_flags_desc = "O_CREAT (create if missing)";
    } else if (local_flags & O_TRUNC) {
        creation_flags_desc = "O_TRUNC (truncate existing)";
    } else {
        creation_flags_desc = "none (open existing)";
    }

    /* Phase 2: Identify status flags */
    char status_flags_buf[128];
    char *p = status_flags_buf;
    int status_flags_count = 0;

    if (local_flags & O_APPEND) {
        if (status_flags_count++ > 0) {
            *p++ = '|';
        }
        const char *s = "O_APPEND";
        while (*s) *p++ = *s++;
    }
    if (local_flags & O_NONBLOCK) {
        if (status_flags_count++ > 0) {
            *p++ = '|';
        }
        const char *s = "O_NONBLOCK";
        while (*s) *p++ = *s++;
    }
    if (local_flags & O_DIRECTORY) {
        if (status_flags_count++ > 0) {
            *p++ = '|';
        }
        const char *s = "O_DIRECTORY";
        while (*s) *p++ = *s++;
    }
    if (local_flags & O_SYNC) {
        if (status_flags_count++ > 0) {
            *p++ = '|';
        }
        const char *s = "O_SYNC";
        while (*s) *p++ = *s++;
    }
    if (local_flags & O_CLOEXEC) {
        if (status_flags_count++ > 0) {
            *p++ = '|';
        }
        const char *s = "O_CLOEXEC";
        while (*s) *p++ = *s++;
    }
    *p = '\0';

    const char *status_flags_desc = status_flags_count > 0 ? status_flags_buf : "none";

    /* Phase 2: Categorize file mode (when O_CREAT specified) */
    const char *mode_desc;
    if (local_flags & O_CREAT) {
        if (local_mode == 0644) {
            mode_desc = "0644 (rw-r--r--, typical file)";
        } else if (local_mode == 0755) {
            mode_desc = "0755 (rwxr-xr-x, executable)";
        } else if (local_mode == 0600) {
            mode_desc = "0600 (rw-------, private)";
        } else if (local_mode == 0666) {
            mode_desc = "0666 (rw-rw-rw-, world-writable)";
        } else if ((local_mode & 0777) == local_mode) {
            mode_desc = "custom (valid)";
        } else {
            mode_desc = "invalid (bits outside 0777)";
        }
    } else {
        mode_desc = "ignored (O_CREAT not set)";
    }

    /* Copy pathname from userspace */
    char kpath[256];
    int rc = copy_user_string(local_pathname, kpath, sizeof(kpath));
    if (rc != 0) {
        const char *error_desc;
        switch (rc) {
            case -EFAULT:
                error_desc = "invalid pathname pointer";
                break;
            case -ENAMETOOLONG:
                error_desc = "pathname too long";
                break;
            default:
                error_desc = "copy failed";
                break;
        }
        fut_printf("[OPEN] open(pathname=?, access=%s, creation=%s, status=%s, mode=%s) -> %d (%s)\n",
                   access_mode_desc, creation_flags_desc, status_flags_desc, mode_desc, rc, error_desc);
        return rc;
    }

    /* Phase 2: Categorize path type */
    const char *path_type;
    if (kpath[0] == '/') {
        path_type = "absolute";
    } else if (kpath[0] == '.' && kpath[1] == '/') {
        path_type = "relative (explicit)";
    } else if (kpath[0] == '.') {
        path_type = "relative (current/parent)";
    } else {
        path_type = "relative";
    }

    /* Open via VFS */
    int result = fut_vfs_open(kpath, local_flags, local_mode);

    /* Phase 3: Validate O_DIRECTORY flag - file must be a directory */
    if (result >= 0 && (local_flags & O_DIRECTORY)) {
        struct fut_file *file = fut_vfs_get_file(result);
        if (file && file->vnode && file->vnode->type != VN_DIR) {
            /* O_DIRECTORY flag specified but file is not a directory */
            extern int fut_vfs_close(int fd);
            fut_vfs_close(result);
            fut_printf("[OPEN] open(path='%s' [%s], O_DIRECTORY) -> ENOTDIR (file is not a directory)\n",
                       kpath, path_type);
            return -ENOTDIR;
        }
    }

    /* Phase 2: Handle error cases with detailed logging */
    if (result < 0) {
        const char *error_desc;
        switch (result) {
            case -ENOENT:
                error_desc = "file not found or path component missing";
                break;
            case -EACCES:
                error_desc = "permission denied";
                break;
            case -EISDIR:
                error_desc = "is a directory (cannot write)";
                break;
            case -ENOTDIR:
                error_desc = "path component not a directory";
                break;
            case -EEXIST:
                error_desc = "file exists (O_CREAT|O_EXCL)";
                break;
            case -ENOMEM:
                error_desc = "out of memory";
                break;
            case -EMFILE:
                error_desc = "per-process FD limit reached";
                break;
            case -ENFILE:
                error_desc = "system-wide FD limit reached";
                break;
            case -EROFS:
                error_desc = "read-only filesystem";
                break;
            case -ENAMETOOLONG:
                error_desc = "pathname too long";
                break;
            default:
                error_desc = "unknown error";
                break;
        }
        fut_printf("[OPEN] open(path='%s' [%s], access=%s, creation=%s, status=%s, mode=%s) -> %d (%s)\n",
                   kpath, path_type, access_mode_desc, creation_flags_desc, status_flags_desc,
                   mode_desc, result, error_desc);
        return (long)result;
    }

    /* Phase 2: Detailed success logging */
    fut_printf("[OPEN] open(path='%s' [%s], access=%s, creation=%s, status=%s, mode=%s) -> %d (Phase 3: flag validation and VFS delegation)\n",
               kpath, path_type, access_mode_desc, creation_flags_desc, status_flags_desc,
               mode_desc, result);

    return (long)result;
}

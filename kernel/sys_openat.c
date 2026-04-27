/* kernel/sys_openat.c - Open file relative to directory descriptor
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements openat() to open files relative to directory file descriptors.
 * More secure than open() for avoiding race conditions.
 */

#include <kernel/fut_task.h>
#include <kernel/fut_vfs.h>
#include <kernel/uaccess.h>
#include <kernel/errno.h>
#include <subsystems/posix_syscall.h>
#include <stddef.h>
#include <string.h>

#include <kernel/kprintf.h>
#include <fcntl.h>

/* copy_user_string provided by subsystems/posix_syscall.h */
/* AT_* and O_* constants provided by fcntl.h */
#ifndef FD_CLOEXEC
#define FD_CLOEXEC 1
#endif

/* ── O_TMPFILE helpers ────────────────────────────────────────── */

static uint64_t g_tmpfile_seq = 0;

/* Build a 16-char lowercase hex string of val into buf (no NUL appended). */
static void u64_to_hex16(uint64_t val, char *buf) {
    static const char hex[] = "0123456789abcdef";
    for (int i = 15; i >= 0; i--) {
        buf[i] = hex[val & 0xf];
        val >>= 4;
    }
}

/*
 * Handle O_TMPFILE: resolve the directory, create an anonymous file inside it,
 * unlink the name, and return the open fd.  The file persists until the last
 * fd is closed.
 *
 * @param task      current task
 * @param dirfd     directory fd or AT_FDCWD
 * @param kpath     kernel-space directory path (already copied from user)
 * @param flags     original open flags (O_TMPFILE | O_DIRECTORY included)
 * @param mode      creation mode
 */
static long openat_tmpfile(fut_task_t *task, int dirfd, const char *kpath,
                            int flags, int mode) {
    /* Resolve to absolute directory path */
    char abs_dir[256];
    int rret = fut_vfs_resolve_at(task, dirfd, kpath, abs_dir, sizeof(abs_dir));
    if (rret < 0)
        return rret;

    /* Build unique temp name: <dir>/.#tmpXXXXXXXXXXXXXXXX */
    uint64_t seq = __atomic_fetch_add(&g_tmpfile_seq, 1, __ATOMIC_RELAXED);
    char tmp_path[280];
    size_t dlen = strlen(abs_dir);
    /* Strip trailing slashes (keep at least '/') */
    while (dlen > 1 && abs_dir[dlen - 1] == '/')
        dlen--;
    if (dlen + 1 + 6 + 16 + 1 > sizeof(tmp_path))
        return -ENAMETOOLONG;
    memcpy(tmp_path, abs_dir, dlen);
    tmp_path[dlen++] = '/';
    tmp_path[dlen++] = '.';
    tmp_path[dlen++] = '#';
    tmp_path[dlen++] = 't';
    tmp_path[dlen++] = 'm';
    tmp_path[dlen++] = 'p';
    u64_to_hex16(seq, tmp_path + dlen);
    dlen += 16;
    tmp_path[dlen] = '\0';

    /* Strip O_TMPFILE (and O_DIRECTORY which it includes); add O_CREAT|O_EXCL */
    int create_flags = (flags & ~O_TMPFILE) | O_CREAT | O_EXCL;

    int fd = (int)fut_vfs_open(tmp_path, create_flags, mode);
    if (fd < 0)
        return fd;

    /* Unlink the directory entry immediately → file becomes anonymous */
    int uret = fut_vfs_unlink(tmp_path);
    if (uret < 0) {
        fut_vfs_close(fd);
        return uret;
    }

    /* Apply O_CLOEXEC if requested */
    if ((flags & O_CLOEXEC) && task && task->fd_flags && fd < task->max_fds)
        task->fd_flags[fd] |= FD_CLOEXEC;

    return (long)fd;
}

/**
 * openat() - Open file relative to directory file descriptor
 *
 * Opens file relative to directory fd. If pathname is absolute, dirfd is
 * ignored. If pathname is relative and dirfd is AT_FDCWD, pathname is
 * relative to current working directory.
 *
 * @param dirfd    Directory file descriptor or AT_FDCWD
 * @param pathname Path to file (absolute or relative to dirfd)
 * @param flags    Open flags
 * @param mode     Permission mode if creating
 *
 * Returns:
 *   - Non-negative file descriptor on success
 *   - Same errors as open()
 *   - -EBADF if dirfd is invalid and pathname is relative
 *   - -ENOTDIR if dirfd is not a directory
 *
 * Phase 1 (Completed): Basic openat with AT_FDCWD support
 * Phase 2 (Completed): Enhanced validation, flag analysis, and detailed logging
 * Phase 3 (Completed): Support real dirfd (relative opens)
 * Phase 4: Advanced flags (O_TMPFILE, O_DIRECT, etc.)
 */
long sys_openat(int dirfd, const char *pathname, int flags, int mode) {
    /* ARM64 FIX: Copy parameters to local variables to survive blocking calls */
    int local_dirfd = dirfd;
    const char *local_pathname = pathname;
    int local_flags = flags;
    /* Mask creation mode to S_IALLUGO (07777) per Linux do_filp_open —
     * same fix as sys_open. */
    int local_mode = mode & 07777;

    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Phase 2: Validate pathname pointer */
    if (!local_pathname) {
        fut_printf("[OPENAT] openat(dirfd=%d, pathname=NULL, flags=0x%x, mode=0%o) -> EFAULT\n",
                   local_dirfd, local_flags, local_mode);
        return -EFAULT;
    }

    /* Security hardening - Path truncation detection
     * VULNERABILITY: Silent Path Truncation Leading to Unauthorized File Access
     *
     * ATTACK SCENARIO:
     * Attacker provides path longer than 256 bytes to exploit truncation
     *
     * Example attack:
     * 1. Attacker calls openat(AT_FDCWD, long_path, O_RDONLY, 0)
     * 2. long_path = "/etc/passwd" + [240 bytes of padding] + "_fake"
     * 3. copy_user_string truncates at 256 bytes
     * 4. Kernel path becomes "/etc/passwd" + [246 bytes] (NULL terminated)
     * 5. VFS opens /etc/passwd instead of intended _fake suffixed path
     * 6. Attacker gains access to sensitive file
     *
     * Real-world exploitation:
     * - Access /etc/shadow by providing /etc/shadow + padding
     * - Bypass path-based ACLs via truncation to allowed prefix
     * - Create files in protected directories (truncate suffix)
     * - Symlink confusion via truncated target paths
     *
     * DEFENSE:
     * Verify path was not truncated during copy
     * - copy_user_string returns 0 on success with NULL termination
     * - Validate that kpath is properly NULL-terminated
     * - Check if source path length exceeds buffer capacity
     * - Return -ENAMETOOLONG if truncation detected
     */
    char kpath[256];
    int rc = copy_user_string(local_pathname, kpath, sizeof(kpath));
    if (rc != 0) {
        fut_printf("[OPENAT] openat(dirfd=%d, pathname=?, flags=0x%x, mode=0%o) -> %d (copy failed)\n",
                   local_dirfd, local_flags, local_mode, rc);
        return rc;
    }

    /* Verify path was not truncated (NULL terminator must exist somewhere in buffer)
     * If no '\0' found in buffer, the path was truncated and full path exceeds buffer size */
    if (memchr(kpath, '\0', sizeof(kpath)) == NULL) {
        fut_printf("[OPENAT] openat(dirfd=%d, pathname=<truncated>, flags=0x%x, mode=0%o) -> ENAMETOOLONG "
                   "(path exceeds %zu bytes, truncation detected)\n",
                   local_dirfd, local_flags, local_mode, sizeof(kpath) - 1);
        return -ENAMETOOLONG;
    }

    /* Phase 2: Categorize dirfd type */
    const char *dirfd_desc;
    const char *path_type;

    if (local_dirfd == AT_FDCWD) {
        dirfd_desc = "AT_FDCWD (current directory)";
    } else if (local_dirfd >= 0) {
        dirfd_desc = "real fd";
    } else {
        dirfd_desc = "invalid fd";
    }

    if (kpath[0] == '/') {
        path_type = "absolute";
    } else {
        path_type = "relative";
    }

    /* O_CREAT | O_DIRECTORY without O_TMPFILE is invalid on Linux.
     * O_TMPFILE includes O_DIRECTORY, so only reject when the O_TMPFILE
     * high bit (020000000) is absent. */
    if ((local_flags & (O_CREAT | O_DIRECTORY)) == (O_CREAT | O_DIRECTORY) &&
        (local_flags & O_TMPFILE) != O_TMPFILE) {
        return -EINVAL;
    }

    /* O_TMPFILE: create anonymous file in the specified directory.
     * Linux requires O_TMPFILE to be combined with write access — see
     * fs/namei.c:do_tmpfile, where 'if (acc_mode & MAY_WRITE)' is the
     * mandatory gate. An O_TMPFILE | O_RDONLY open is rejected with
     * EINVAL because an anonymous file with no way to write to it is
     * meaningless (it can never be linkat'd into the namespace either,
     * since the link still needs a writable fd). The previous code
     * silently created an unwritable anonymous file. */
    fut_task_t *open_task = fut_task_current();
    if ((local_flags & O_TMPFILE) == O_TMPFILE) {
        int acc = local_flags & O_ACCMODE;
        if (acc != O_WRONLY && acc != O_RDWR) {
            fut_printf("[OPENAT] openat(O_TMPFILE) requires O_WRONLY or O_RDWR "
                       "(acc=0x%x) -> EINVAL\n", acc);
            return -EINVAL;
        }
        return openat_tmpfile(open_task, local_dirfd, kpath, local_flags, local_mode);
    }

    /* Open via VFS, using fut_vfs_open_at to handle dirfd-relative paths */
    int result = fut_vfs_open_at(open_task, local_dirfd, kpath, local_flags, local_mode);

    /* Validate O_DIRECTORY flag — file must be a directory */
    if (result >= 0 && (local_flags & O_DIRECTORY)) {
        struct fut_file *file = fut_vfs_get_file(result);
        if (file && file->vnode && file->vnode->type != VN_DIR) {
            fut_vfs_close(result);
            fut_printf("[OPENAT] openat(dirfd=%d, path='%s', O_DIRECTORY) -> ENOTDIR\n",
                       local_dirfd, kpath);
            return -ENOTDIR;
        }
    }

    /* Set FD_CLOEXEC if O_CLOEXEC was requested (per-FD flag) */
    if (result >= 0 && (local_flags & O_CLOEXEC)) {
        if (open_task && open_task->fd_flags && result < open_task->max_fds)
            open_task->fd_flags[result] |= FD_CLOEXEC;
    }

    if (result < 0) {
        fut_printf("[OPENAT] openat(dirfd=%d [%s], path='%s' [%s], flags=0x%x, mode=0%o) "
                   "-> %d (%s)\n",
                   local_dirfd, dirfd_desc, kpath, path_type, local_flags, local_mode, result,
                   (result == -ENOENT) ? "not found" :
                   (result == -EACCES) ? "access denied" :
                   (result == -EEXIST) ? "already exists" :
                   (result == -EISDIR) ? "is directory" :
                   (result == -ENOTDIR) ? "not directory" :
                   (result == -EBADF) ? "bad dirfd" :
                   (result == -ENOTSUP) ? "not supported" : "error");
    }

    return (long)result;
}

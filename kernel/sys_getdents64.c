/* kernel/sys_getdents64.c - Directory entry reading syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the getdents64() syscall for reading directory entries.
 * Essential for directory listing and filesystem traversal.
 *
 * Phase 1 (Completed): Basic directory entry reading with VFS integration
 * Phase 2 (Current): Enhanced validation, FD/buffer categorization, entry counting, and detailed logging
 * Phase 3: Performance optimization (readdir caching, large directory support)
 * Phase 4: Advanced features (directory entry filtering, sorted traversal)
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);
extern void *fut_malloc(size_t size);
extern void fut_free(void *ptr);
extern int fut_copy_to_user(void *to, const void *from, size_t size);
extern fut_task_t *fut_task_current(void);
extern struct fut_file *vfs_get_file_from_task(struct fut_task *task, int fd);

/* Linux getdents64 dirent structure */
struct linux_dirent64 {
    uint64_t d_ino;
    int64_t  d_off;
    uint16_t d_reclen;
    uint8_t  d_type;
    char     d_name[];
} __attribute__((packed));

/**
 * getdents64() - Read directory entries
 *
 * Reads multiple directory entries from an open directory file descriptor
 * into a buffer. This is the 64-bit version of getdents that supports large
 * inode numbers and offsets. Essential for directory traversal and listing.
 *
 * @param fd     File descriptor of the open directory
 * @param dirp   User-space buffer to store directory entries
 * @param count  Size of the buffer
 *
 * Returns:
 *   - Number of bytes read on success (0 at end of directory)
 *   - -EBADF if fd is not a valid file descriptor
 *   - -ENOTDIR if fd does not refer to a directory
 *   - -EINVAL if buffer size is too small
 *   - -EFAULT if dirp points to invalid memory
 *   - -ENOMEM if kernel buffer allocation fails
 *   - -ESRCH if no current task context
 *
 * Behavior:
 *   - Reads directory entries into buffer
 *   - Returns number of bytes read (0 at end)
 *   - Multiple entries fit in one buffer
 *   - Maintains directory position (cookie)
 *   - Each entry is 8-byte aligned
 *   - Directory traversal is stateful (uses fd offset)
 *
 * Directory entry structure:
 *   - d_ino: Inode number (0 for deleted entries)
 *   - d_off: Offset to next entry
 *   - d_reclen: Length of this entry
 *   - d_type: File type (DT_REG, DT_DIR, etc.)
 *   - d_name: Null-terminated filename
 *
 * File types (d_type):
 *   - DT_REG (8): Regular file
 *   - DT_DIR (4): Directory
 *   - DT_LNK (10): Symbolic link
 *   - DT_CHR (2): Character device
 *   - DT_BLK (6): Block device
 *   - DT_FIFO (1): FIFO/pipe
 *   - DT_SOCK (12): Socket
 *   - DT_UNKNOWN (0): Unknown type
 *
 * Common usage patterns:
 *
 * List directory contents:
 *   int fd = open("/path/to/dir", O_RDONLY | O_DIRECTORY);
 *   char buf[4096];
 *   while (1) {
 *       ssize_t n = getdents64(fd, buf, sizeof(buf));
 *       if (n == 0) break;  // End of directory
 *       if (n < 0) { perror("getdents64"); break; }
 *
 *       struct linux_dirent64 *d;
 *       for (size_t pos = 0; pos < n; ) {
 *           d = (struct linux_dirent64 *)(buf + pos);
 *           printf("%s\n", d->d_name);
 *           pos += d->d_reclen;
 *       }
 *   }
 *   close(fd);
 *
 * Filter by file type:
 *   struct linux_dirent64 *d;
 *   for (size_t pos = 0; pos < n; ) {
 *       d = (struct linux_dirent64 *)(buf + pos);
 *       if (d->d_type == DT_REG) {
 *           printf("File: %s\n", d->d_name);
 *       } else if (d->d_type == DT_DIR) {
 *           printf("Dir: %s\n", d->d_name);
 *       }
 *       pos += d->d_reclen;
 *   }
 *
 * Count directory entries:
 *   int count = 0;
 *   ssize_t n = getdents64(fd, buf, sizeof(buf));
 *   struct linux_dirent64 *d;
 *   for (size_t pos = 0; pos < n; ) {
 *       d = (struct linux_dirent64 *)(buf + pos);
 *       count++;
 *       pos += d->d_reclen;
 *   }
 *
 * Recursive directory traversal:
 *   void traverse(const char *path) {
 *       int fd = open(path, O_RDONLY | O_DIRECTORY);
 *       char buf[4096];
 *       ssize_t n;
 *       while ((n = getdents64(fd, buf, sizeof(buf))) > 0) {
 *           for (size_t pos = 0; pos < n; ) {
 *               struct linux_dirent64 *d = (struct linux_dirent64 *)(buf + pos);
 *               if (d->d_type == DT_DIR && strcmp(d->d_name, ".") != 0 &&
 *                   strcmp(d->d_name, "..") != 0) {
 *                   char subpath[PATH_MAX];
 *                   snprintf(subpath, sizeof(subpath), "%s/%s", path, d->d_name);
 *                   traverse(subpath);
 *               }
 *               pos += d->d_reclen;
 *           }
 *       }
 *       close(fd);
 *   }
 *
 * Special directory entries:
 *   - "." (current directory): Always present
 *   - ".." (parent directory): Always present (except root)
 *   - Hidden files: Start with '.' (Unix convention)
 *
 * Stateful traversal:
 *   - First call starts at beginning
 *   - Subsequent calls continue from last position
 *   - lseek(fd, 0, SEEK_SET) resets to beginning
 *   - Concurrent access requires careful synchronization
 *
 * Buffer size guidelines:
 *   - Minimum: sizeof(linux_dirent64) + 256 (one entry)
 *   - Typical: 4096 bytes (page size, multiple entries)
 *   - Large: 32768 bytes (better performance for large dirs)
 *
 * Performance considerations:
 *   - Larger buffers = fewer syscalls
 *   - 4KB buffer typically optimal
 *   - Large directories benefit from bigger buffers
 *   - Cache locality matters for readdir
 *
 * Security considerations:
 *   - Check fd refers to directory, not regular file
 *   - Validate buffer is writable
 *   - Watch for very long filenames
 *   - Be careful with symbolic links
 *
 * Related syscalls:
 *   - opendir()/readdir(): Higher-level directory reading (libc)
 *   - getdents(): 32-bit version (legacy)
 *   - fdopendir(): Convert fd to DIR*
 *   - rewinddir(): Reset directory position
 *
 * Phase 1 (Completed): Basic directory entry reading with VFS integration
 * Phase 2 (Current): Enhanced validation, FD/buffer categorization, entry counting, detailed logging
 * Phase 3: Performance optimization (readdir caching, large directory support)
 * Phase 4: Advanced features (directory entry filtering, sorted traversal)
 */
long sys_getdents64(unsigned int fd, void *dirp, unsigned int count) {
    /* Phase 2: Validate buffer pointer */
    if (!dirp) {
        fut_printf("[GETDENTS64] getdents64(fd=%u, dirp=NULL, count=%u) -> EFAULT (NULL buffer)\n",
                   fd, count);
        return -EFAULT;
    }

    /* Phase 2: Validate buffer size */
    if (count < sizeof(struct linux_dirent64) + 1) {
        fut_printf("[GETDENTS64] getdents64(fd=%u, dirp=?, count=%u) -> EINVAL "
                   "(buffer too small, min=%zu)\n",
                   fd, count, sizeof(struct linux_dirent64) + 1);
        return -EINVAL;
    }

    /* Phase 2: Get current task for FD table access */
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[GETDENTS64] getdents64(fd=%u, count=%u) -> ESRCH (no current task)\n",
                   fd, count);
        return -ESRCH;
    }

    /* Phase 2: Categorize FD range */
    const char *fd_category;
    if (fd <= 2) {
        fd_category = "stdio (0-2)";
    } else if (fd < 10) {
        fd_category = "low (3-9)";
    } else if (fd < 100) {
        fd_category = "normal (10-99)";
    } else if (fd < 1000) {
        fd_category = "high (100-999)";
    } else {
        fd_category = "very high (≥1000)";
    }

    /* Phase 2: Categorize buffer size */
    const char *count_category;
    if (count < 1024) {
        count_category = "small (<1 KB)";
    } else if (count == 4096) {
        count_category = "optimal (4 KB)";
    } else if (count < 8192) {
        count_category = "medium (<8 KB)";
    } else if (count < 32768) {
        count_category = "large (<32 KB)";
    } else {
        count_category = "very large (≥32 KB)";
    }

    /* Validate FD table exists */
    if (!task->fd_table) {
        fut_printf("[GETDENTS64] getdents64(fd=%u [%s], count=%u [%s]) -> EBADF "
                   "(no FD table, pid=%d)\n", fd, fd_category, count, count_category, task->pid);
        return -EBADF;
    }

    /* Get file structure from FD */
    struct fut_file *file = vfs_get_file_from_task(task, (int)fd);
    if (!file) {
        fut_printf("[GETDENTS64] getdents64(fd=%u [%s], count=%u [%s]) -> EBADF "
                   "(fd not open, pid=%d)\n", fd, fd_category, count, count_category, task->pid);
        return -EBADF;
    }

    /* Phase 2: Validate this is a directory */
    if (!file->vnode || file->vnode->type != VN_DIR) {
        const char *file_type = "unknown";
        if (file->vnode) {
            switch (file->vnode->type) {
                case VN_REG: file_type = "regular file"; break;
                case VN_CHR: file_type = "character device"; break;
                case VN_BLK: file_type = "block device"; break;
                case VN_LNK: file_type = "symbolic link"; break;
                case VN_FIFO: file_type = "FIFO"; break;
                case VN_SOCK: file_type = "socket"; break;
                default: break;
            }
        }
        fut_printf("[GETDENTS64] getdents64(fd=%u [%s], type=%s, count=%u [%s]) -> ENOTDIR "
                   "(not a directory, pid=%d)\n",
                   fd, fd_category, file_type, count, count_category, task->pid);
        return -ENOTDIR;
    }

    /* Allocate kernel buffer for directory entries */
    void *kbuf = fut_malloc(count);
    if (!kbuf) {
        fut_printf("[GETDENTS64] getdents64(fd=%u [%s], ino=%lu, count=%u [%s]) -> ENOMEM "
                   "(kernel buffer allocation failed, pid=%d)\n",
                   fd, fd_category, file->vnode->ino, count, count_category, task->pid);
        return -ENOMEM;
    }

    uint64_t cookie = 0;
    size_t total_bytes = 0;
    char *buf_ptr = (char *)kbuf;
    int entry_count = 0;

    /* Read directory entries using VFS */
    while (total_bytes < count) {
        struct fut_vdirent vdirent;
        int rc = fut_vfs_readdir_fd((int)fd, &cookie, &vdirent);

        if (rc < 0) {
            if (total_bytes == 0) {
                const char *error_desc;
                switch (rc) {
                    case -EBADF:
                        error_desc = "invalid file descriptor";
                        break;
                    case -ENOTDIR:
                        error_desc = "not a directory";
                        break;
                    default:
                        error_desc = "readdir error";
                        break;
                }
                fut_printf("[GETDENTS64] getdents64(fd=%u [%s], ino=%lu, count=%u [%s]) -> %d "
                           "(%s, pid=%d)\n",
                           fd, fd_category, file->vnode->ino, count, count_category,
                           rc, error_desc, task->pid);
                fut_free(kbuf);
                return rc;  /* Error on first entry */
            }
            break;  /* No more entries */
        }

        if (rc == 0) {
            break;  /* End of directory */
        }

        /* Calculate required size for this entry */
        size_t name_len = 0;
        while (vdirent.d_name[name_len] != '\0' && name_len < 256) {
            name_len++;
        }

        /* Align to 8-byte boundary for next entry */
        size_t reclen = sizeof(struct linux_dirent64) + name_len + 1;
        reclen = (reclen + 7) & ~7;

        if (total_bytes + reclen > count) {
            break;  /* Not enough space for this entry */
        }

        /* Build linux_dirent64 entry */
        struct linux_dirent64 *dent = (struct linux_dirent64 *)buf_ptr;
        dent->d_ino = vdirent.d_ino;
        dent->d_off = (int64_t)cookie;
        dent->d_reclen = (uint16_t)reclen;
        dent->d_type = vdirent.d_type;

        /* Copy name */
        for (size_t i = 0; i <= name_len; i++) {
            dent->d_name[i] = vdirent.d_name[i];
        }

        buf_ptr += reclen;
        total_bytes += reclen;
        entry_count++;
    }

    /* Copy to userspace */
    if (total_bytes > 0) {
        if (fut_copy_to_user(dirp, kbuf, total_bytes) != 0) {
            fut_printf("[GETDENTS64] getdents64(fd=%u [%s], ino=%lu, count=%u [%s], "
                       "entries=%d, bytes=%zu) -> EFAULT (copy_to_user failed, pid=%d)\n",
                       fd, fd_category, file->vnode->ino, count, count_category,
                       entry_count, total_bytes, task->pid);
            fut_free(kbuf);
            return -EFAULT;
        }
    }

    fut_free(kbuf);

    /* Phase 2: Detailed success logging */
    const char *eof_marker = (total_bytes == 0) ? " (EOF)" : "";
    fut_printf("[GETDENTS64] getdents64(fd=%u [%s], ino=%lu, count=%u [%s], "
               "entries=%d, bytes=%zu%s) -> %zu (Phase 2)\n",
               fd, fd_category, file->vnode->ino, count, count_category,
               entry_count, total_bytes, eof_marker, total_bytes);
    return (long)total_bytes;
}

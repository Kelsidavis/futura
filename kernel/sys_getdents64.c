/* kernel/sys_getdents64.c - Directory entry reading syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the getdents64() syscall for reading directory entries.
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);
extern void *fut_malloc(size_t size);
extern void fut_free(void *ptr);
extern int fut_copy_to_user(void *to, const void *from, size_t size);

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
 * inode numbers and offsets.
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
 */
long sys_getdents64(unsigned int fd, void *dirp, unsigned int count) {
    if (count < sizeof(struct linux_dirent64) + 1) {
        return -EINVAL;
    }

    /* Allocate kernel buffer for directory entries */
    void *kbuf = fut_malloc(count);
    if (!kbuf) {
        return -ENOMEM;
    }

    uint64_t cookie = 0;
    size_t total_bytes = 0;
    char *buf_ptr = (char *)kbuf;

    /* Read directory entries using VFS */
    while (total_bytes < count) {
        struct fut_vdirent vdirent;
        int rc = fut_vfs_readdir_fd((int)fd, &cookie, &vdirent);

        if (rc < 0) {
            if (total_bytes == 0) {
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
    }

    /* Copy to userspace */
    if (total_bytes > 0) {
        if (fut_copy_to_user(dirp, kbuf, total_bytes) != 0) {
            fut_free(kbuf);
            return -EFAULT;
        }
    }

    fut_free(kbuf);
    return (long)total_bytes;
}

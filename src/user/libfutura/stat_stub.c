// SPDX-License-Identifier: MPL-2.0

#include <errno.h>

#include <user/sys.h>

/* lstat() — retrieve file metadata without following a terminal symlink.
 * The kernel implements lstat (x86_64) / newfstatat+AT_SYMLINK_NOFOLLOW
 * (ARM64); these wrappers forward to it so tools like 'ls -l' and 'find'
 * can tell symlinks apart from their targets instead of always failing. */
int lstat64(const char *path, void *buf) {
    long rc = sys_lstat_call(path, buf);
    if (rc < 0) {
        errno = (int)-rc;
        return -1;
    }
    return 0;
}

/* lstat wrapper - aliases not supported on some toolchains */
int lstat(const char *path, void *buf) {
    return lstat64(path, buf);
}

/* kernel/tests/sys_vfs.c - VFS correctness tests
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Tests for VFS correctness features:
 *   - sys_vfs_trunc: O_TRUNC truncates existing file content to zero
 *   - sys_vfs_append: O_APPEND writes always append to end of file
 *   - sys_vfs_relpath: relative path resolution using task cwd
 *   - sys_vfs_mkdir_stat: directory mtime updates on file creation
 *   - sys_vfs_readlink: create and read back a symbolic link
 *   - sys_vfs_link: create hard link and verify shared inode
 *   - sys_vfs_mount: mount/umount ramfs, verify isolated file namespace
 */

#include <kernel/fut_task.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_object.h>
#include <kernel/errno.h>
#include <kernel/kprintf.h>
#include <stddef.h>
#include <string.h>
#include <fcntl.h>
#include "tests/test_api.h"

/* Test identifiers (for fut_test_fail error codes) */
#define VFS_TEST_TRUNC      1
#define VFS_TEST_APPEND     2
#define VFS_TEST_RELPATH    3
#define VFS_TEST_DIR_MTIME  4
#define VFS_TEST_READLINK   5
#define VFS_TEST_LINK       6
#define VFS_TEST_MOUNT      7
#define VFS_TEST_RENAME2    8
#define VFS_TEST_INOTIFY    9
#define VFS_TEST_UMOUNT_EXPIRE 10
#define VFS_TEST_DOTDOT     11
#define VFS_TEST_EISDIR     12
#define VFS_TEST_CHDIR_DOTDOT 13
#define VFS_TEST_INOTIFY_RENAME 14
#define VFS_TEST_INOTIFY_ATTRIB  15
#define VFS_TEST_INOTIFY_CLOSE   16
#define VFS_TEST_INOTIFY_ACCESS  17
#define VFS_TEST_INOTIFY_MODIFY  18

/* Use kernel-level VFS functions (no copy_from_user) */
#define sys_mkdir(path, mode)           fut_vfs_mkdir(path, (uint32_t)(mode))
#define sys_chdir(path)                 fut_vfs_chdir(path)
#define sys_symlink(target, linkpath)   fut_vfs_symlink(target, linkpath)
#define sys_readlink(path, buf, sz)     fut_vfs_readlink(path, buf, sz)
#define sys_link(old, new)              fut_vfs_link(old, new)

/* inotify syscall declarations */
extern long sys_inotify_init1(int flags);
extern long sys_inotify_add_watch(int fd, const char *pathname, uint32_t mask);
extern long sys_inotify_rm_watch(int fd, int wd);
extern long sys_renameat2(int olddirfd, const char *oldpath,
                          int newdirfd, const char *newpath,
                          unsigned int flags);

/* inotify event structure (mirrors kernel/sys_inotify.c) */
struct test_inotify_event {
    int      wd;
    uint32_t mask;
    uint32_t cookie;
    uint32_t len;
};
#define IN_CREATE     0x00000100U
#define IN_MODIFY     0x00000002U
#define IN_DELETE     0x00000200U
#define IN_MOVED_FROM 0x00000040U
#define IN_MOVED_TO   0x00000080U
#define IN_MOVE       (IN_MOVED_FROM | IN_MOVED_TO)
#define IN_ATTRIB          0x00000004U
#define IN_CLOSE_WRITE     0x00000008U
#define IN_CLOSE_NOWRITE   0x00000010U
#define IN_ACCESS          0x00000001U
#define IN_OPEN            0x00000020U
#define IN_NONBLOCK 00004000
#define RENAME_NOREPLACE (1U << 0)
#define RENAME_EXCHANGE  (1U << 1)

/* ------------------------------------------------------------------ */

static void test_otrunc(void) {
    fut_printf("[VFS-TEST] Test 1: O_TRUNC truncates existing file\n");

    const char *path = "/vfs_trunc_test.txt";

    /* Create file with initial content */
    int fd = fut_vfs_open(path, O_WRONLY | O_CREAT, 0644);
    if (fd < 0) {
        fut_printf("[VFS-TEST] ✗ O_TRUNC: failed to create file (%d)\n", fd);
        fut_test_fail(VFS_TEST_TRUNC);
        return;
    }
    const char *data = "Hello, world!";
    ssize_t w = fut_vfs_write(fd, data, 13);
    fut_vfs_close(fd);
    if (w != 13) {
        fut_printf("[VFS-TEST] ✗ O_TRUNC: initial write failed (%zd)\n", w);
        fut_test_fail(VFS_TEST_TRUNC);
        return;
    }

    /* Reopen with O_TRUNC */
    fd = fut_vfs_open(path, O_RDWR | O_TRUNC, 0644);
    if (fd < 0) {
        fut_printf("[VFS-TEST] ✗ O_TRUNC: reopen failed (%d)\n", fd);
        fut_test_fail(VFS_TEST_TRUNC);
        return;
    }

    /* Read back — should be empty */
    char buf[32];
    ssize_t r = fut_vfs_read(fd, buf, sizeof(buf));
    fut_vfs_close(fd);

    if (r != 0) {
        fut_printf("[VFS-TEST] ✗ O_TRUNC: expected 0 bytes, got %zd\n", r);
        fut_test_fail(VFS_TEST_TRUNC);
        return;
    }

    fut_printf("[VFS-TEST] ✓ O_TRUNC: file truncated to zero\n");
    fut_test_pass();
}

/* ------------------------------------------------------------------ */

static void test_oappend(void) {
    fut_printf("[VFS-TEST] Test 2: O_APPEND always writes at end of file\n");

    const char *path = "/vfs_append_test.txt";

    /* Create file with initial content */
    int fd = fut_vfs_open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        fut_printf("[VFS-TEST] ✗ O_APPEND: create failed (%d)\n", fd);
        fut_test_fail(VFS_TEST_APPEND);
        return;
    }
    const char *first = "AAA";
    fut_vfs_write(fd, first, 3);
    fut_vfs_close(fd);

    /* Open with O_APPEND and write */
    fd = fut_vfs_open(path, O_WRONLY | O_APPEND, 0644);
    if (fd < 0) {
        fut_printf("[VFS-TEST] ✗ O_APPEND: reopen failed (%d)\n", fd);
        fut_test_fail(VFS_TEST_APPEND);
        return;
    }
    const char *second = "BBB";
    ssize_t w = fut_vfs_write(fd, second, 3);
    fut_vfs_close(fd);
    if (w != 3) {
        fut_printf("[VFS-TEST] ✗ O_APPEND: write failed (%zd)\n", w);
        fut_test_fail(VFS_TEST_APPEND);
        return;
    }

    /* Read back the whole file */
    fd = fut_vfs_open(path, O_RDONLY, 0);
    if (fd < 0) {
        fut_printf("[VFS-TEST] ✗ O_APPEND: final open failed (%d)\n", fd);
        fut_test_fail(VFS_TEST_APPEND);
        return;
    }
    char buf[16];
    ssize_t r = fut_vfs_read(fd, buf, sizeof(buf) - 1);
    fut_vfs_close(fd);
    if (r != 6) {
        fut_printf("[VFS-TEST] ✗ O_APPEND: expected 6 bytes, got %zd\n", r);
        fut_test_fail(VFS_TEST_APPEND);
        return;
    }
    buf[r] = '\0';
    if (buf[0] != 'A' || buf[1] != 'A' || buf[2] != 'A' ||
        buf[3] != 'B' || buf[4] != 'B' || buf[5] != 'B') {
        fut_printf("[VFS-TEST] ✗ O_APPEND: content mismatch: '%s'\n", buf);
        fut_test_fail(VFS_TEST_APPEND);
        return;
    }

    fut_printf("[VFS-TEST] ✓ O_APPEND: content is AAABBB as expected\n");
    fut_test_pass();
}

/* ------------------------------------------------------------------ */

static void test_relpath(void) {
    fut_printf("[VFS-TEST] Test 3: relative path resolution via cwd\n");

    /* Create a directory to use as cwd */
    const char *dir = "/vfs_relpath_dir";
    long mkdir_ret = sys_mkdir(dir, 0755);
    if (mkdir_ret < 0 && (int)mkdir_ret != -17 /* EEXIST */) {
        fut_printf("[VFS-TEST] ✗ relpath: mkdir failed (%ld)\n", mkdir_ret);
        fut_test_fail(VFS_TEST_RELPATH);
        return;
    }

    /* Change into that directory */
    long chdir_ret = sys_chdir(dir);
    if (chdir_ret < 0) {
        fut_printf("[VFS-TEST] ✗ relpath: chdir failed (%ld)\n", chdir_ret);
        fut_test_fail(VFS_TEST_RELPATH);
        return;
    }

    /* Create a file using a relative path */
    int fd = fut_vfs_open("relfile.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        fut_printf("[VFS-TEST] ✗ relpath: open relative path failed (%d)\n", fd);
        sys_chdir("/");
        fut_test_fail(VFS_TEST_RELPATH);
        return;
    }
    const char *msg = "relative";
    fut_vfs_write(fd, msg, 8);
    fut_vfs_close(fd);

    /* Read back via absolute path to confirm it was created in the right place */
    fd = fut_vfs_open("/vfs_relpath_dir/relfile.txt", O_RDONLY, 0);
    if (fd < 0) {
        fut_printf("[VFS-TEST] ✗ relpath: absolute open failed (%d)\n", fd);
        sys_chdir("/");
        fut_test_fail(VFS_TEST_RELPATH);
        return;
    }
    char buf[16];
    ssize_t r = fut_vfs_read(fd, buf, sizeof(buf) - 1);
    fut_vfs_close(fd);

    /* Return to root */
    sys_chdir("/");

    if (r != 8 || buf[0] != 'r') {
        fut_printf("[VFS-TEST] ✗ relpath: content mismatch (r=%zd)\n", r);
        fut_test_fail(VFS_TEST_RELPATH);
        return;
    }

    fut_printf("[VFS-TEST] ✓ relative path: file created at correct absolute location\n");
    fut_test_pass();
}

/* ------------------------------------------------------------------ */

static void test_dir_mtime(void) {
    fut_printf("[VFS-TEST] Test 4: directory mtime updates on file creation\n");

    const char *dir = "/vfs_mtime_dir";
    long mkdir_ret = sys_mkdir(dir, 0755);
    if (mkdir_ret < 0 && (int)mkdir_ret != -17 /* EEXIST */) {
        fut_printf("[VFS-TEST] ✗ dir_mtime: mkdir failed (%ld)\n", mkdir_ret);
        fut_test_fail(VFS_TEST_DIR_MTIME);
        return;
    }

    /* Stat directory before creating a file */
    struct fut_stat st_before;
    int ret = fut_vfs_stat(dir, &st_before);
    if (ret < 0) {
        fut_printf("[VFS-TEST] ✗ dir_mtime: stat before failed (%d)\n", ret);
        fut_test_fail(VFS_TEST_DIR_MTIME);
        return;
    }

    /* Create a file inside the directory */
    const char *file = "/vfs_mtime_dir/newfile.txt";
    int fd = fut_vfs_open(file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        fut_printf("[VFS-TEST] ✗ dir_mtime: create file failed (%d)\n", fd);
        fut_test_fail(VFS_TEST_DIR_MTIME);
        return;
    }
    fut_vfs_close(fd);

    /* Stat directory after creating a file */
    struct fut_stat st_after;
    ret = fut_vfs_stat(dir, &st_after);
    if (ret < 0) {
        fut_printf("[VFS-TEST] ✗ dir_mtime: stat after failed (%d)\n", ret);
        fut_test_fail(VFS_TEST_DIR_MTIME);
        return;
    }

    /* mtime should be >= before (may be equal if ticks haven't advanced) */
    if (st_after.st_mtime < st_before.st_mtime) {
        fut_printf("[VFS-TEST] ✗ dir_mtime: mtime went backwards (%llu < %llu)\n",
                   (unsigned long long)st_after.st_mtime,
                   (unsigned long long)st_before.st_mtime);
        fut_test_fail(VFS_TEST_DIR_MTIME);
        return;
    }

    fut_printf("[VFS-TEST] ✓ dir mtime: before=%llu after=%llu (non-decreasing)\n",
               (unsigned long long)st_before.st_mtime,
               (unsigned long long)st_after.st_mtime);
    fut_test_pass();
}

/* ------------------------------------------------------------------ */

static void test_readlink(void) {
    fut_printf("[VFS-TEST] Test 5: symlink create and readlink\n");

    const char *target = "/vfs_link_target.txt";
    const char *linkpath = "/vfs_test_symlink";

    /* Create target file */
    int fd = fut_vfs_open(target, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        fut_printf("[VFS-TEST] ✗ readlink: target create failed (%d)\n", fd);
        fut_test_fail(VFS_TEST_READLINK);
        return;
    }
    fut_vfs_close(fd);

    /* Create symlink */
    long sym_ret = sys_symlink(target, linkpath);
    if (sym_ret < 0) {
        fut_printf("[VFS-TEST] ✗ readlink: symlink failed (%ld)\n", sym_ret);
        fut_test_fail(VFS_TEST_READLINK);
        return;
    }

    /* Read the symlink */
    char buf[64];
    long r = sys_readlink(linkpath, buf, sizeof(buf) - 1);
    if (r < 0) {
        fut_printf("[VFS-TEST] ✗ readlink: readlink failed (%ld)\n", r);
        fut_test_fail(VFS_TEST_READLINK);
        return;
    }
    buf[r] = '\0';

    /* Verify content matches target */
    size_t target_len = 0;
    while (target[target_len]) target_len++;
    if ((size_t)r != target_len) {
        fut_printf("[VFS-TEST] ✗ readlink: length mismatch (got %ld, expected %zu)\n",
                   r, target_len);
        fut_test_fail(VFS_TEST_READLINK);
        return;
    }
    for (size_t i = 0; i < target_len; i++) {
        if (buf[i] != target[i]) {
            fut_printf("[VFS-TEST] ✗ readlink: content mismatch at byte %zu\n", i);
            fut_test_fail(VFS_TEST_READLINK);
            return;
        }
    }

    fut_printf("[VFS-TEST] ✓ readlink: '%s' -> '%s'\n", linkpath, buf);
    fut_test_pass();
}

/* ------------------------------------------------------------------ */

static void test_hardlink(void) {
    fut_printf("[VFS-TEST] Test 6: hard link shares inode with original\n");

    const char *orig = "/vfs_hardlink_orig.txt";
    const char *link = "/vfs_hardlink_link.txt";

    /* Create original file */
    int fd = fut_vfs_open(orig, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        fut_printf("[VFS-TEST] ✗ hardlink: create failed (%d)\n", fd);
        fut_test_fail(VFS_TEST_LINK);
        return;
    }
    const char *content = "hardlink-data";
    fut_vfs_write(fd, content, 13);
    fut_vfs_close(fd);

    /* Create hard link */
    long link_ret = sys_link(orig, link);
    if (link_ret < 0) {
        fut_printf("[VFS-TEST] ✗ hardlink: link() failed (%ld)\n", link_ret);
        fut_test_fail(VFS_TEST_LINK);
        return;
    }

    /* Stat both and verify same inode */
    struct fut_stat st_orig, st_link;
    int r1 = fut_vfs_stat(orig, &st_orig);
    int r2 = fut_vfs_stat(link, &st_link);
    if (r1 < 0 || r2 < 0) {
        fut_printf("[VFS-TEST] ✗ hardlink: stat failed (r1=%d r2=%d)\n", r1, r2);
        fut_test_fail(VFS_TEST_LINK);
        return;
    }

    if (st_orig.st_ino != st_link.st_ino) {
        fut_printf("[VFS-TEST] ✗ hardlink: inodes differ (%llu vs %llu)\n",
                   (unsigned long long)st_orig.st_ino,
                   (unsigned long long)st_link.st_ino);
        fut_test_fail(VFS_TEST_LINK);
        return;
    }

    if (st_link.st_nlink < 2) {
        fut_printf("[VFS-TEST] ✗ hardlink: nlink=%u expected >=2\n", st_link.st_nlink);
        fut_test_fail(VFS_TEST_LINK);
        return;
    }

    /* Read back content through the link */
    fd = fut_vfs_open(link, O_RDONLY, 0);
    if (fd < 0) {
        fut_printf("[VFS-TEST] ✗ hardlink: open via link failed (%d)\n", fd);
        fut_test_fail(VFS_TEST_LINK);
        return;
    }
    char buf[20];
    ssize_t bytes = fut_vfs_read(fd, buf, sizeof(buf) - 1);
    fut_vfs_close(fd);

    if (bytes != 13 || buf[0] != 'h') {
        fut_printf("[VFS-TEST] ✗ hardlink: content mismatch via link (%zd bytes)\n", bytes);
        fut_test_fail(VFS_TEST_LINK);
        return;
    }

    fut_printf("[VFS-TEST] ✓ hard link: same inode %llu, nlink=%u\n",
               (unsigned long long)st_orig.st_ino, st_orig.st_nlink);
    fut_test_pass();
}

/* ------------------------------------------------------------------ */

static void test_mount(void) {
    fut_printf("[VFS-TEST] Test 7: mount/umount creates isolated ramfs namespace\n");

    /* Create mount point directory */
    const char *mntpoint = "/vfs_test_mnt";
    int ret = fut_vfs_mkdir(mntpoint, 0755);
    if (ret < 0 && ret != -EEXIST) {
        fut_printf("[VFS-TEST] ✗ mount: mkdir failed (%d)\n", ret);
        fut_test_fail(VFS_TEST_MOUNT);
        return;
    }

    /* Mount a fresh ramfs at the mount point */
    ret = fut_vfs_mount(NULL, mntpoint, "ramfs", 0, NULL, FUT_INVALID_HANDLE);
    if (ret < 0) {
        fut_printf("[VFS-TEST] ✗ mount: fut_vfs_mount failed (%d)\n", ret);
        fut_test_fail(VFS_TEST_MOUNT);
        return;
    }

    /* Create a file inside the mounted filesystem */
    const char *testfile = "/vfs_test_mnt/mount_test.txt";
    int fd = fut_vfs_open(testfile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        fut_printf("[VFS-TEST] ✗ mount: open in mounted fs failed (%d)\n", fd);
        fut_vfs_unmount(mntpoint);
        fut_test_fail(VFS_TEST_MOUNT);
        return;
    }
    const char *content = "mount-test";
    ssize_t nw = fut_vfs_write(fd, content, 10);
    fut_vfs_close(fd);
    if (nw != 10) {
        fut_printf("[VFS-TEST] ✗ mount: write in mounted fs failed (%zd)\n", nw);
        fut_vfs_unmount(mntpoint);
        fut_test_fail(VFS_TEST_MOUNT);
        return;
    }

    /* Read back to verify */
    fd = fut_vfs_open(testfile, O_RDONLY, 0);
    if (fd < 0) {
        fut_printf("[VFS-TEST] ✗ mount: re-open failed (%d)\n", fd);
        fut_vfs_unmount(mntpoint);
        fut_test_fail(VFS_TEST_MOUNT);
        return;
    }
    char buf[16];
    ssize_t nr = fut_vfs_read(fd, buf, sizeof(buf) - 1);
    fut_vfs_close(fd);
    if (nr != 10 || buf[0] != 'm') {
        fut_printf("[VFS-TEST] ✗ mount: read-back mismatch (%zd bytes)\n", nr);
        fut_vfs_unmount(mntpoint);
        fut_test_fail(VFS_TEST_MOUNT);
        return;
    }

    /* Unmount */
    ret = fut_vfs_unmount(mntpoint);
    if (ret < 0) {
        fut_printf("[VFS-TEST] ✗ mount: umount failed (%d)\n", ret);
        fut_test_fail(VFS_TEST_MOUNT);
        return;
    }

    /* After unmount the file should no longer be visible */
    fd = fut_vfs_open(testfile, O_RDONLY, 0);
    if (fd >= 0) {
        fut_printf("[VFS-TEST] ✗ mount: file still accessible after umount (fd=%d)\n", fd);
        fut_vfs_close(fd);
        fut_test_fail(VFS_TEST_MOUNT);
        return;
    }

    fut_printf("[VFS-TEST] ✓ mount: ramfs mounted, file written/read, umounted, file gone\n");
    fut_test_pass();
}

/* ------------------------------------------------------------------ */

static void test_umount_expire(void) {
    fut_printf("[VFS-TEST] Test 10: umount2 MNT_EXPIRE mark then unmount semantics\n");

    const char *mntpoint = "/vfs_expire_mnt";
    const char *testfile = "/vfs_expire_mnt/expire.txt";

    int ret = fut_vfs_mkdir(mntpoint, 0755);
    if (ret < 0 && ret != -EEXIST) {
        fut_printf("[VFS-TEST] ✗ umount expire: mkdir failed (%d)\n", ret);
        fut_test_fail(VFS_TEST_UMOUNT_EXPIRE);
        return;
    }

    ret = fut_vfs_mount(NULL, mntpoint, "ramfs", 0, NULL, FUT_INVALID_HANDLE);
    if (ret < 0) {
        fut_printf("[VFS-TEST] ✗ umount expire: mount failed (%d)\n", ret);
        fut_test_fail(VFS_TEST_UMOUNT_EXPIRE);
        return;
    }

    int fd = fut_vfs_open(testfile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        fut_printf("[VFS-TEST] ✗ umount expire: create file failed (%d)\n", fd);
        fut_vfs_unmount(mntpoint);
        fut_test_fail(VFS_TEST_UMOUNT_EXPIRE);
        return;
    }
    fut_vfs_close(fd);

    ret = fut_vfs_expire_mount(mntpoint);
    if (ret != -EAGAIN) {
        fut_printf("[VFS-TEST] ✗ umount expire: first expire returned %d (expected -EAGAIN)\n", ret);
        fut_vfs_unmount(mntpoint);
        fut_test_fail(VFS_TEST_UMOUNT_EXPIRE);
        return;
    }

    ret = fut_vfs_expire_mount(mntpoint);
    if (ret != 0) {
        fut_printf("[VFS-TEST] ✗ umount expire: second expire returned %d (expected 0)\n", ret);
        fut_vfs_unmount(mntpoint);
        fut_test_fail(VFS_TEST_UMOUNT_EXPIRE);
        return;
    }

    fd = fut_vfs_open(testfile, O_RDONLY, 0);
    if (fd >= 0) {
        fut_printf("[VFS-TEST] ✗ umount expire: file still visible after expire unmount (fd=%d)\n", fd);
        fut_vfs_close(fd);
        fut_test_fail(VFS_TEST_UMOUNT_EXPIRE);
        return;
    }

    fut_printf("[VFS-TEST] ✓ umount expire: first call marked, second call unmounted mountpoint\n");
    fut_test_pass();
}

/* ------------------------------------------------------------------ */

/*
 * test_renameat2 — verify RENAME_NOREPLACE and RENAME_EXCHANGE semantics.
 */
static void test_renameat2(void) {
    fut_printf("[VFS-TEST] Test 8: renameat2 RENAME_NOREPLACE semantics\n");

    const char *src = "/vfs_rename2_src.txt";
    const char *dst = "/vfs_rename2_dst.txt";

    /* Create source file */
    int fd = fut_vfs_open(src, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        fut_printf("[VFS-TEST] ✗ renameat2: failed to create src (%d)\n", fd);
        fut_test_fail(VFS_TEST_RENAME2);
        return;
    }
    fut_vfs_write(fd, "hello", 5);
    fut_vfs_close(fd);

    /* Create destination file so it already exists */
    fd = fut_vfs_open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        fut_printf("[VFS-TEST] ✗ renameat2: failed to create dst (%d)\n", fd);
        fut_test_fail(VFS_TEST_RENAME2);
        return;
    }
    fut_vfs_write(fd, "world", 5);
    fut_vfs_close(fd);

    int ret = (int)sys_renameat2(AT_FDCWD, src, AT_FDCWD, dst, RENAME_NOREPLACE);
    if (ret != -EEXIST) {
        fut_printf("[VFS-TEST] ✗ renameat2: RENAME_NOREPLACE returned %d (expected -EEXIST)\n", ret);
        fut_test_fail(VFS_TEST_RENAME2);
        return;
    }
    fut_printf("[VFS-TEST]   dst exists (RENAME_NOREPLACE correctly detects EEXIST)\n");

    /* Confirm src still exists (rename did not happen) */
    fd = fut_vfs_open(src, O_RDONLY, 0);
    if (fd < 0) {
        fut_printf("[VFS-TEST] ✗ renameat2: src disappeared unexpectedly (%d)\n", fd);
        fut_test_fail(VFS_TEST_RENAME2);
        return;
    }
    fut_vfs_close(fd);

    ret = (int)sys_renameat2(AT_FDCWD, src, AT_FDCWD, dst, RENAME_EXCHANGE);
    if (ret != 0) {
        fut_printf("[VFS-TEST] ✗ renameat2: RENAME_EXCHANGE returned %d\n", ret);
        fut_test_fail(VFS_TEST_RENAME2);
        return;
    }

    char buf[8] = {0};
    fd = fut_vfs_open(src, O_RDONLY, 0);
    if (fd < 0) {
        fut_printf("[VFS-TEST] ✗ renameat2: src missing after exchange (%d)\n", fd);
        fut_test_fail(VFS_TEST_RENAME2);
        return;
    }
    ssize_t nr = fut_vfs_read(fd, buf, 5);
    fut_vfs_close(fd);
    if (nr != 5 || memcmp(buf, "world", 5) != 0) {
        fut_printf("[VFS-TEST] ✗ renameat2: src content after exchange invalid (nr=%zd)\n", nr);
        fut_test_fail(VFS_TEST_RENAME2);
        return;
    }

    memset(buf, 0, sizeof(buf));
    fd = fut_vfs_open(dst, O_RDONLY, 0);
    if (fd < 0) {
        fut_printf("[VFS-TEST] ✗ renameat2: dst missing after exchange (%d)\n", fd);
        fut_test_fail(VFS_TEST_RENAME2);
        return;
    }
    nr = fut_vfs_read(fd, buf, 5);
    fut_vfs_close(fd);
    if (nr != 5 || memcmp(buf, "hello", 5) != 0) {
        fut_printf("[VFS-TEST] ✗ renameat2: dst content after exchange invalid (nr=%zd)\n", nr);
        fut_test_fail(VFS_TEST_RENAME2);
        return;
    }

    fut_printf("[VFS-TEST] ✓ renameat2: RENAME_NOREPLACE and RENAME_EXCHANGE verified\n");
    fut_test_pass();
}

/* ------------------------------------------------------------------ */

/*
 * Test 9: inotify IN_CREATE event delivered when a file is created
 * in a watched directory.
 *
 * Uses IN_NONBLOCK so the read doesn't block if the event wasn't queued.
 */
static void test_inotify(void) {
    fut_printf("[VFS-TEST] Test 9: inotify IN_CREATE event delivery\n");

    /* Watch root directory; event delivery is validated there in current VFS. */
    const char *watch_dir = "/";

    /* Create inotify fd in non-blocking mode */
    int ifd = (int)sys_inotify_init1(IN_NONBLOCK);
    if (ifd < 0) {
        fut_printf("[VFS-TEST] ✗ inotify_init1 returned %d\n", ifd);
        fut_test_fail(VFS_TEST_INOTIFY);
        return;
    }

    /* Add watch for IN_CREATE */
    int wd = (int)sys_inotify_add_watch(ifd, watch_dir, IN_CREATE);
    if (wd < 0) {
        fut_printf("[VFS-TEST] ✗ inotify_add_watch returned %d\n", wd);
        fut_vfs_close(ifd);
        fut_test_fail(VFS_TEST_INOTIFY);
        return;
    }

    /* Create a file in the watched directory — should dispatch IN_CREATE */
    const char *test_file = "/inotify_watch_newfile.txt";
    const char *expected_name = "inotify_watch_newfile.txt";
    fut_vfs_unlink(test_file); /* Best-effort cleanup from previous runs */
    int fd = fut_vfs_open(test_file, O_CREAT | O_RDWR, 0644);
    if (fd < 0) {
        fut_printf("[VFS-TEST] ✗ inotify: create test file failed %d\n", fd);
        sys_inotify_rm_watch(ifd, wd);
        fut_vfs_close(ifd);
        fut_test_fail(VFS_TEST_INOTIFY);
        return;
    }
    fut_vfs_close(fd);

    /* Read event from inotify fd — buffer large enough for header + padded name */
    char buf[sizeof(struct test_inotify_event) + 256];
    ssize_t n = fut_vfs_read(ifd, buf, sizeof(buf));
    fut_vfs_close(ifd);

    if (n < (ssize_t)sizeof(struct test_inotify_event)) {
        fut_printf("[VFS-TEST] ✗ inotify read returned %ld (expected >= %zu)\n",
                   n, sizeof(struct test_inotify_event));
        fut_test_fail(VFS_TEST_INOTIFY);
        return;
    }

    struct test_inotify_event *ep = (struct test_inotify_event *)buf;

    if (ep->wd != wd) {
        fut_printf("[VFS-TEST] ✗ inotify event wd=%d expected %d\n", ep->wd, wd);
        fut_test_fail(VFS_TEST_INOTIFY);
        return;
    }

    if (!(ep->mask & IN_CREATE)) {
        fut_printf("[VFS-TEST] ✗ inotify event mask=0x%x missing IN_CREATE\n", ep->mask);
        fut_test_fail(VFS_TEST_INOTIFY);
        return;
    }

    /* Verify filename is included in the event (Phase 5) */
    if (ep->len == 0) {
        fut_printf("[VFS-TEST] ✗ inotify event len=0, expected name '%s'\n", expected_name);
        fut_test_fail(VFS_TEST_INOTIFY);
        return;
    }
    const char *got_name = buf + sizeof(struct test_inotify_event);
    if (strcmp(got_name, expected_name) != 0) {
        fut_printf("[VFS-TEST] ✗ inotify event name='%s' expected '%s'\n",
                   got_name, expected_name);
        fut_test_fail(VFS_TEST_INOTIFY);
        return;
    }

    fut_printf("[VFS-TEST] ✓ inotify: IN_CREATE event received (wd=%d mask=0x%x name='%s')\n",
               ep->wd, ep->mask, got_name);
    fut_test_pass();
}

/* ------------------------------------------------------------------ */

/*
 * Test 14: inotify IN_MOVED_FROM/IN_MOVED_TO events with matching cookie
 * on rename within a watched directory.
 */
static void test_inotify_rename(void) {
    fut_printf("[VFS-TEST] Test 14: inotify IN_MOVED_FROM/IN_MOVED_TO with cookie\n");

    const char *watch_dir  = "/";
    const char *src_path   = "/inotify_rename_src.txt";
    const char *dst_path   = "/inotify_rename_dst.txt";
    const char *src_name   = "inotify_rename_src.txt";
    const char *dst_name   = "inotify_rename_dst.txt";

    /* Create the source file */
    fut_vfs_unlink(src_path);
    fut_vfs_unlink(dst_path);
    int fd = fut_vfs_open(src_path, O_CREAT | O_RDWR, 0644);
    if (fd < 0) {
        fut_printf("[VFS-TEST] ✗ inotify_rename: create src failed %d\n", fd);
        fut_test_fail(VFS_TEST_INOTIFY_RENAME);
        return;
    }
    fut_vfs_close(fd);

    /* Create inotify fd watching for IN_MOVE */
    int ifd = (int)sys_inotify_init1(IN_NONBLOCK);
    if (ifd < 0) {
        fut_printf("[VFS-TEST] ✗ inotify_rename: inotify_init1 returned %d\n", ifd);
        fut_vfs_unlink(src_path);
        fut_test_fail(VFS_TEST_INOTIFY_RENAME);
        return;
    }

    int wd = (int)sys_inotify_add_watch(ifd, watch_dir, IN_MOVE);
    if (wd < 0) {
        fut_printf("[VFS-TEST] ✗ inotify_rename: inotify_add_watch returned %d\n", wd);
        fut_vfs_close(ifd);
        fut_vfs_unlink(src_path);
        fut_test_fail(VFS_TEST_INOTIFY_RENAME);
        return;
    }

    /* Perform the rename — should fire IN_MOVED_FROM then IN_MOVED_TO */
    extern long sys_rename(const char *oldpath, const char *newpath);
    int ret = (int)sys_rename(src_path, dst_path);
    if (ret != 0) {
        fut_printf("[VFS-TEST] ✗ inotify_rename: rename returned %d\n", ret);
        sys_inotify_rm_watch(ifd, wd);
        fut_vfs_close(ifd);
        fut_vfs_unlink(src_path);
        fut_test_fail(VFS_TEST_INOTIFY_RENAME);
        return;
    }

    /* Read both events — buffer for two events with names */
    char buf[2 * (sizeof(struct test_inotify_event) + 256)];
    ssize_t n = fut_vfs_read(ifd, buf, sizeof(buf));
    sys_inotify_rm_watch(ifd, wd);
    fut_vfs_close(ifd);
    fut_vfs_unlink(dst_path);

    if (n < (ssize_t)(2 * sizeof(struct test_inotify_event))) {
        fut_printf("[VFS-TEST] ✗ inotify_rename: read returned %ld (need at least 2 events)\n", n);
        fut_test_fail(VFS_TEST_INOTIFY_RENAME);
        return;
    }

    /* First event must be IN_MOVED_FROM with src_name */
    struct test_inotify_event *ev1 = (struct test_inotify_event *)buf;
    if (!(ev1->mask & IN_MOVED_FROM)) {
        fut_printf("[VFS-TEST] ✗ inotify_rename: first event mask=0x%x missing IN_MOVED_FROM\n",
                   ev1->mask);
        fut_test_fail(VFS_TEST_INOTIFY_RENAME);
        return;
    }
    const char *name1 = buf + sizeof(struct test_inotify_event);
    if (strcmp(name1, src_name) != 0) {
        fut_printf("[VFS-TEST] ✗ inotify_rename: MOVED_FROM name='%s' expected '%s'\n",
                   name1, src_name);
        fut_test_fail(VFS_TEST_INOTIFY_RENAME);
        return;
    }

    /* Second event must be IN_MOVED_TO with dst_name */
    size_t ev1_size = sizeof(struct test_inotify_event) + ev1->len;
    if ((ssize_t)(ev1_size + sizeof(struct test_inotify_event)) > n) {
        fut_printf("[VFS-TEST] ✗ inotify_rename: buffer too small for second event\n");
        fut_test_fail(VFS_TEST_INOTIFY_RENAME);
        return;
    }
    struct test_inotify_event *ev2 = (struct test_inotify_event *)(buf + ev1_size);
    if (!(ev2->mask & IN_MOVED_TO)) {
        fut_printf("[VFS-TEST] ✗ inotify_rename: second event mask=0x%x missing IN_MOVED_TO\n",
                   ev2->mask);
        fut_test_fail(VFS_TEST_INOTIFY_RENAME);
        return;
    }
    const char *name2 = buf + ev1_size + sizeof(struct test_inotify_event);
    if (strcmp(name2, dst_name) != 0) {
        fut_printf("[VFS-TEST] ✗ inotify_rename: MOVED_TO name='%s' expected '%s'\n",
                   name2, dst_name);
        fut_test_fail(VFS_TEST_INOTIFY_RENAME);
        return;
    }

    /* Cookies must match and be non-zero */
    if (ev1->cookie == 0 || ev1->cookie != ev2->cookie) {
        fut_printf("[VFS-TEST] ✗ inotify_rename: cookie mismatch: from=%u to=%u\n",
                   ev1->cookie, ev2->cookie);
        fut_test_fail(VFS_TEST_INOTIFY_RENAME);
        return;
    }

    fut_printf("[VFS-TEST] ✓ inotify rename: MOVED_FROM='%s' cookie=%u, MOVED_TO='%s' cookie=%u\n",
               name1, ev1->cookie, name2, ev2->cookie);
    fut_test_pass();
}

/* ------------------------------------------------------------------ */

/* Test 11: .. path resolution traverses to parent directory */
static void test_dotdot(void) {
    fut_printf("[VFS-TEST] Test 11: '..' parent directory traversal\n");

    /* Create /dotdot_test/sub/file.txt */
    int ret = fut_vfs_mkdir("/dotdot_test", 0755);
    if (ret != 0 && ret != -EEXIST) {
        fut_printf("[VFS-TEST] ✗ mkdir /dotdot_test failed: %d\n", ret);
        fut_test_fail(VFS_TEST_DOTDOT);
        return;
    }
    ret = fut_vfs_mkdir("/dotdot_test/sub", 0755);
    if (ret != 0 && ret != -EEXIST) {
        fut_printf("[VFS-TEST] ✗ mkdir /dotdot_test/sub failed: %d\n", ret);
        fut_test_fail(VFS_TEST_DOTDOT);
        return;
    }

    int fd = fut_vfs_open("/dotdot_test/marker.txt", O_WRONLY | O_CREAT, 0644);
    if (fd < 0) {
        fut_printf("[VFS-TEST] ✗ create marker.txt failed: %d\n", fd);
        fut_test_fail(VFS_TEST_DOTDOT);
        return;
    }
    fut_vfs_write(fd, "MARK", 4);
    fut_vfs_close(fd);

    /* Access marker.txt via /dotdot_test/sub/../marker.txt */
    fd = fut_vfs_open("/dotdot_test/sub/../marker.txt", O_RDONLY, 0);
    if (fd < 0) {
        fut_printf("[VFS-TEST] ✗ open via '..' path failed: %d\n", fd);
        fut_test_fail(VFS_TEST_DOTDOT);
        return;
    }

    char buf[8] = {0};
    ssize_t nr = fut_vfs_read(fd, buf, sizeof(buf));
    fut_vfs_close(fd);

    if (nr != 4 || memcmp(buf, "MARK", 4) != 0) {
        fut_printf("[VFS-TEST] ✗ read via '..' path: nr=%zd buf='%s'\n", nr, buf);
        fut_test_fail(VFS_TEST_DOTDOT);
        return;
    }

    /* Also verify /../dotdot_test/marker.txt (.. at root stays at root) */
    fd = fut_vfs_open("/../dotdot_test/marker.txt", O_RDONLY, 0);
    if (fd < 0) {
        fut_printf("[VFS-TEST] ✗ open via '/..' path failed: %d\n", fd);
        fut_test_fail(VFS_TEST_DOTDOT);
        return;
    }

    memset(buf, 0, sizeof(buf));
    nr = fut_vfs_read(fd, buf, sizeof(buf));
    fut_vfs_close(fd);

    if (nr != 4 || memcmp(buf, "MARK", 4) != 0) {
        fut_printf("[VFS-TEST] ✗ read via '/..' path: nr=%zd\n", nr);
        fut_test_fail(VFS_TEST_DOTDOT);
        return;
    }

    fut_printf("[VFS-TEST] ✓ '..' path resolution: single and double parent traversal works\n");
    fut_test_pass();
}

/* Test 12: read() on directory returns EISDIR */
static void test_read_dir_eisdir(void) {
    fut_printf("[VFS-TEST] Test 12: read() on directory returns EISDIR\n");

    int fd = fut_vfs_open("/", O_RDONLY, 0);
    if (fd < 0) {
        fut_printf("[VFS-TEST] ✗ open('/') failed: %d\n", fd);
        fut_test_fail(VFS_TEST_EISDIR);
        return;
    }

    char buf[16];
    ssize_t nr = fut_vfs_read(fd, buf, sizeof(buf));
    fut_vfs_close(fd);

    if (nr != -EISDIR) {
        fut_printf("[VFS-TEST] ✗ read(dir_fd) returned %zd (expected -EISDIR=%d)\n",
                   nr, -EISDIR);
        fut_test_fail(VFS_TEST_EISDIR);
        return;
    }

    fut_printf("[VFS-TEST] ✓ read() on directory correctly returns EISDIR\n");
    fut_test_pass();
}

/* sys_chdir is already defined as a macro to fut_vfs_chdir */

/* Test 13: chdir with '..' normalizes path and getcwd returns clean result */
static void test_chdir_with_dotdot(void) {
    fut_printf("[VFS-TEST] Test 13: chdir with '..' normalization\n");

    /* Ensure directories exist (reuse from dotdot test) */
    fut_vfs_mkdir("/cd_test", 0755);
    fut_vfs_mkdir("/cd_test/sub", 0755);

    /* chdir into the subdirectory */
    long ret = sys_chdir("/cd_test/sub");
    if (ret != 0) {
        fut_printf("[VFS-TEST] ✗ chdir(/cd_test/sub) failed: %ld\n", ret);
        sys_chdir("/");
        fut_test_fail(VFS_TEST_CHDIR_DOTDOT);
        return;
    }

    /* Create a file using relative path to verify we're in the right place */
    int fd = fut_vfs_open("marker.txt", O_WRONLY | O_CREAT, 0644);
    if (fd < 0) {
        fut_printf("[VFS-TEST] ✗ relative create in sub failed: %d\n", fd);
        sys_chdir("/");
        fut_test_fail(VFS_TEST_CHDIR_DOTDOT);
        return;
    }
    fut_vfs_write(fd, "SUB", 3);
    fut_vfs_close(fd);

    /* chdir to parent via '..' */
    ret = sys_chdir("..");
    if (ret != 0) {
        fut_printf("[VFS-TEST] ✗ chdir(..) failed: %ld\n", ret);
        sys_chdir("/");
        fut_test_fail(VFS_TEST_CHDIR_DOTDOT);
        return;
    }

    /* Verify we're in /cd_test by opening sub/marker.txt relatively */
    fd = fut_vfs_open("sub/marker.txt", O_RDONLY, 0);
    if (fd < 0) {
        fut_printf("[VFS-TEST] ✗ relative open after chdir(..) failed: %d\n", fd);
        sys_chdir("/");
        fut_test_fail(VFS_TEST_CHDIR_DOTDOT);
        return;
    }
    char buf[4] = {0};
    ssize_t nr = fut_vfs_read(fd, buf, 3);
    fut_vfs_close(fd);

    sys_chdir("/");

    if (nr != 3 || memcmp(buf, "SUB", 3) != 0) {
        fut_printf("[VFS-TEST] ✗ content mismatch after chdir(..): nr=%zd\n", nr);
        fut_test_fail(VFS_TEST_CHDIR_DOTDOT);
        return;
    }

    fut_printf("[VFS-TEST] ✓ chdir(..): navigated up, relative paths work correctly\n");
    fut_test_pass();
}

/*
 * Test 15: inotify IN_ATTRIB event on chmod
 *
 * Creates a file, watches its parent directory for IN_ATTRIB, calls chmod,
 * then reads the inotify event and verifies mask and filename.
 */
static void test_inotify_attrib(void) {
    fut_printf("[VFS-TEST] Test 15: inotify IN_ATTRIB event on chmod\n");
    extern long sys_chmod(const char *pathname, uint32_t mode);

    const char *watch_dir  = "/";
    const char *filepath   = "/attrib_test.txt";
    const char *filename   = "attrib_test.txt";

    /* Create the file */
    fut_vfs_unlink(filepath);
    int fd = fut_vfs_open(filepath, O_CREAT | O_RDWR, 0644);
    if (fd < 0) {
        fut_printf("[VFS-TEST] ✗ inotify_attrib: create file failed %d\n", fd);
        fut_test_fail(VFS_TEST_INOTIFY_ATTRIB);
        return;
    }
    fut_vfs_close(fd);

    /* Watch root for IN_ATTRIB */
    int ifd = (int)sys_inotify_init1(IN_NONBLOCK);
    if (ifd < 0) {
        fut_printf("[VFS-TEST] ✗ inotify_attrib: inotify_init1 failed %d\n", ifd);
        fut_vfs_unlink(filepath);
        fut_test_fail(VFS_TEST_INOTIFY_ATTRIB);
        return;
    }

    int wd = (int)sys_inotify_add_watch(ifd, watch_dir, IN_ATTRIB);
    if (wd < 0) {
        fut_printf("[VFS-TEST] ✗ inotify_attrib: add_watch failed %d\n", wd);
        fut_vfs_close(ifd);
        fut_vfs_unlink(filepath);
        fut_test_fail(VFS_TEST_INOTIFY_ATTRIB);
        return;
    }

    /* chmod the file */
    long ret = sys_chmod(filepath, 0600);
    if (ret != 0) {
        fut_printf("[VFS-TEST] ✗ inotify_attrib: chmod failed %ld\n", ret);
        fut_vfs_close(ifd);
        fut_vfs_unlink(filepath);
        fut_test_fail(VFS_TEST_INOTIFY_ATTRIB);
        return;
    }

    /* Read the inotify event */
    char buf[sizeof(struct test_inotify_event) + 64];
    long n = fut_vfs_read(ifd, buf, sizeof(buf));
    if (n < (long)sizeof(struct test_inotify_event)) {
        fut_printf("[VFS-TEST] ✗ inotify_attrib: read returned %ld\n", n);
        fut_vfs_close(ifd);
        fut_vfs_unlink(filepath);
        fut_test_fail(VFS_TEST_INOTIFY_ATTRIB);
        return;
    }

    struct test_inotify_event *ev = (struct test_inotify_event *)buf;
    if (!(ev->mask & IN_ATTRIB)) {
        fut_printf("[VFS-TEST] ✗ inotify_attrib: mask=0x%x missing IN_ATTRIB\n", ev->mask);
        fut_vfs_close(ifd);
        fut_vfs_unlink(filepath);
        fut_test_fail(VFS_TEST_INOTIFY_ATTRIB);
        return;
    }

    const char *got_name = buf + sizeof(struct test_inotify_event);
    if (ev->len > 0 && __builtin_strcmp(got_name, filename) != 0) {
        fut_printf("[VFS-TEST] ✗ inotify_attrib: name='%s' expected '%s'\n",
                   got_name, filename);
        fut_vfs_close(ifd);
        fut_vfs_unlink(filepath);
        fut_test_fail(VFS_TEST_INOTIFY_ATTRIB);
        return;
    }

    fut_vfs_close(ifd);
    fut_vfs_unlink(filepath);
    fut_printf("[VFS-TEST] ✓ inotify IN_ATTRIB: chmod generated mask=0x%x name='%s'\n",
               ev->mask, ev->len > 0 ? got_name : "(none)");
    fut_test_pass();
}

/*
 * Test 16: inotify IN_OPEN / IN_CLOSE_WRITE events on open/close
 *
 * Watches a directory, opens+closes a file for writing, verifies
 * IN_OPEN and IN_CLOSE_WRITE are dispatched with the correct name.
 */
static void test_inotify_close(void) {
    fut_printf("[VFS-TEST] Test 16: inotify IN_OPEN / IN_CLOSE_WRITE on open/close\n");

    const char *watch_dir = "/";
    const char *filepath  = "/close_test.txt";

    fut_vfs_unlink(filepath);

    /* Watch root for IN_OPEN | IN_CLOSE_WRITE | IN_CLOSE_NOWRITE */
    int ifd = (int)sys_inotify_init1(IN_NONBLOCK);
    if (ifd < 0) {
        fut_printf("[VFS-TEST] ✗ inotify_close: inotify_init1 failed %d\n", ifd);
        fut_test_fail(VFS_TEST_INOTIFY_CLOSE);
        return;
    }

    uint32_t watch_mask = IN_OPEN | IN_CLOSE_WRITE | IN_CLOSE_NOWRITE;
    int wd = (int)sys_inotify_add_watch(ifd, watch_dir, watch_mask);
    if (wd < 0) {
        fut_printf("[VFS-TEST] ✗ inotify_close: add_watch failed %d\n", wd);
        fut_vfs_close(ifd);
        fut_test_fail(VFS_TEST_INOTIFY_CLOSE);
        return;
    }

    /* Open file for writing → should generate IN_OPEN */
    int fd = fut_vfs_open(filepath, O_CREAT | O_WRONLY, 0644);
    if (fd < 0) {
        fut_printf("[VFS-TEST] ✗ inotify_close: open failed %d\n", fd);
        fut_vfs_close(ifd);
        fut_test_fail(VFS_TEST_INOTIFY_CLOSE);
        return;
    }

    /* Close the file → should generate IN_CLOSE_WRITE */
    fut_vfs_close(fd);

    /* Read events: expect at least IN_OPEN and IN_CLOSE_WRITE */
    char buf[4 * (sizeof(struct test_inotify_event) + 64)];
    long n = fut_vfs_read(ifd, buf, sizeof(buf));
    if (n < (long)sizeof(struct test_inotify_event)) {
        fut_printf("[VFS-TEST] ✗ inotify_close: read returned %ld\n", n);
        fut_vfs_close(ifd);
        fut_vfs_unlink(filepath);
        fut_test_fail(VFS_TEST_INOTIFY_CLOSE);
        return;
    }

    /* Walk events and check for IN_OPEN and IN_CLOSE_WRITE */
    uint32_t seen = 0;
    char *p = buf;
    char *end = buf + n;
    while (p + (long)sizeof(struct test_inotify_event) <= end) {
        struct test_inotify_event *ev = (struct test_inotify_event *)p;
        if (ev->mask & (IN_OPEN | IN_CLOSE_WRITE | IN_CLOSE_NOWRITE))
            seen |= ev->mask & (IN_OPEN | IN_CLOSE_WRITE | IN_CLOSE_NOWRITE);
        p += sizeof(struct test_inotify_event) + ev->len;
    }

    fut_vfs_close(ifd);
    fut_vfs_unlink(filepath);

    if (!(seen & IN_OPEN)) {
        fut_printf("[VFS-TEST] ✗ inotify_close: IN_OPEN not seen (seen=0x%x)\n", seen);
        fut_test_fail(VFS_TEST_INOTIFY_CLOSE);
        return;
    }
    if (!(seen & IN_CLOSE_WRITE)) {
        fut_printf("[VFS-TEST] ✗ inotify_close: IN_CLOSE_WRITE not seen (seen=0x%x)\n", seen);
        fut_test_fail(VFS_TEST_INOTIFY_CLOSE);
        return;
    }

    fut_printf("[VFS-TEST] ✓ inotify open/close: IN_OPEN and IN_CLOSE_WRITE both seen (0x%x)\n", seen);
    fut_test_pass();
}

/*
 * Test 17: inotify IN_ACCESS event on read
 *
 * Creates a file with content, watches its parent for IN_ACCESS,
 * reads the file, then verifies IN_ACCESS was dispatched.
 */
static void test_inotify_access(void) {
    fut_printf("[VFS-TEST] Test 17: inotify IN_ACCESS event on read\n");

    const char *watch_dir = "/";
    const char *filepath  = "/access_test.txt";

    /* Create and populate the file */
    fut_vfs_unlink(filepath);
    int fd = fut_vfs_open(filepath, O_CREAT | O_WRONLY, 0644);
    if (fd < 0) {
        fut_printf("[VFS-TEST] ✗ inotify_access: create file failed %d\n", fd);
        fut_test_fail(VFS_TEST_INOTIFY_ACCESS);
        return;
    }
    fut_vfs_write(fd, "hello", 5);
    fut_vfs_close(fd);

    /* Watch for IN_ACCESS */
    int ifd = (int)sys_inotify_init1(IN_NONBLOCK);
    if (ifd < 0) {
        fut_printf("[VFS-TEST] ✗ inotify_access: inotify_init1 failed %d\n", ifd);
        fut_vfs_unlink(filepath);
        fut_test_fail(VFS_TEST_INOTIFY_ACCESS);
        return;
    }

    int wd = (int)sys_inotify_add_watch(ifd, watch_dir, IN_ACCESS);
    if (wd < 0) {
        fut_printf("[VFS-TEST] ✗ inotify_access: add_watch failed %d\n", wd);
        fut_vfs_close(ifd);
        fut_vfs_unlink(filepath);
        fut_test_fail(VFS_TEST_INOTIFY_ACCESS);
        return;
    }

    /* Read the file — should generate IN_ACCESS */
    int rfd = fut_vfs_open(filepath, O_RDONLY, 0);
    if (rfd < 0) {
        fut_printf("[VFS-TEST] ✗ inotify_access: open for read failed %d\n", rfd);
        fut_vfs_close(ifd);
        fut_vfs_unlink(filepath);
        fut_test_fail(VFS_TEST_INOTIFY_ACCESS);
        return;
    }
    char rbuf[16];
    fut_vfs_read(rfd, rbuf, sizeof(rbuf));
    fut_vfs_close(rfd);

    /* Check for IN_ACCESS event */
    char buf[sizeof(struct test_inotify_event) + 64];
    long n = fut_vfs_read(ifd, buf, sizeof(buf));
    fut_vfs_close(ifd);
    fut_vfs_unlink(filepath);

    if (n < (long)sizeof(struct test_inotify_event)) {
        fut_printf("[VFS-TEST] ✗ inotify_access: no event (read returned %ld)\n", n);
        fut_test_fail(VFS_TEST_INOTIFY_ACCESS);
        return;
    }

    struct test_inotify_event *ev = (struct test_inotify_event *)buf;
    if (!(ev->mask & IN_ACCESS)) {
        fut_printf("[VFS-TEST] ✗ inotify_access: mask=0x%x missing IN_ACCESS\n", ev->mask);
        fut_test_fail(VFS_TEST_INOTIFY_ACCESS);
        return;
    }

    fut_printf("[VFS-TEST] ✓ inotify IN_ACCESS: read generated mask=0x%x\n", ev->mask);
    fut_test_pass();
}

static void test_inotify_modify(void) {
    fut_printf("[VFS-TEST] Test 18: inotify IN_MODIFY event on write\n");

    const char *watch_dir = "/";
    const char *filepath  = "/modify_test.txt";

    /* Create the file */
    fut_vfs_unlink(filepath);
    int fd = fut_vfs_open(filepath, O_CREAT | O_WRONLY, 0644);
    if (fd < 0) {
        fut_printf("[VFS-TEST] ✗ inotify_modify: create failed %d\n", fd);
        fut_test_fail(VFS_TEST_INOTIFY_MODIFY);
        return;
    }
    fut_vfs_close(fd);

    /* Watch for IN_MODIFY */
    int ifd = (int)sys_inotify_init1(IN_NONBLOCK);
    if (ifd < 0) {
        fut_printf("[VFS-TEST] ✗ inotify_modify: inotify_init1 failed %d\n", ifd);
        fut_vfs_unlink(filepath);
        fut_test_fail(VFS_TEST_INOTIFY_MODIFY);
        return;
    }

    int wd = (int)sys_inotify_add_watch(ifd, watch_dir, IN_MODIFY);
    if (wd < 0) {
        fut_printf("[VFS-TEST] ✗ inotify_modify: add_watch failed %d\n", wd);
        fut_vfs_close(ifd);
        fut_vfs_unlink(filepath);
        fut_test_fail(VFS_TEST_INOTIFY_MODIFY);
        return;
    }

    /* Write to the file — should generate IN_MODIFY */
    int wfd = fut_vfs_open(filepath, O_WRONLY, 0);
    if (wfd < 0) {
        fut_printf("[VFS-TEST] ✗ inotify_modify: open for write failed %d\n", wfd);
        fut_vfs_close(ifd);
        fut_vfs_unlink(filepath);
        fut_test_fail(VFS_TEST_INOTIFY_MODIFY);
        return;
    }
    fut_vfs_write(wfd, "data", 4);
    fut_vfs_close(wfd);

    /* Check for IN_MODIFY event */
    char buf[sizeof(struct test_inotify_event) + 64];
    long n = fut_vfs_read(ifd, buf, sizeof(buf));
    fut_vfs_close(ifd);
    fut_vfs_unlink(filepath);

    if (n < (long)sizeof(struct test_inotify_event)) {
        fut_printf("[VFS-TEST] ✗ inotify_modify: no event (read returned %ld)\n", n);
        fut_test_fail(VFS_TEST_INOTIFY_MODIFY);
        return;
    }

    struct test_inotify_event *ev = (struct test_inotify_event *)buf;
    if (!(ev->mask & IN_MODIFY)) {
        fut_printf("[VFS-TEST] ✗ inotify_modify: mask=0x%x missing IN_MODIFY\n", ev->mask);
        fut_test_fail(VFS_TEST_INOTIFY_MODIFY);
        return;
    }

    fut_printf("[VFS-TEST] ✓ inotify IN_MODIFY: write generated mask=0x%x\n", ev->mask);
    fut_test_pass();
}

void fut_vfs_test_thread(void *arg) {
    (void)arg;

    fut_printf("[VFS-TEST] Starting VFS correctness tests\n");

    test_otrunc();
    test_oappend();
    test_relpath();
    test_dir_mtime();
    test_readlink();
    test_hardlink();
    test_inotify();
    test_inotify_rename();
    test_inotify_attrib();
    test_inotify_close();
    test_inotify_access();
    test_inotify_modify();
    test_mount();
    test_umount_expire();
    test_renameat2();
    test_dotdot();
    test_read_dir_eisdir();
    test_chdir_with_dotdot();

    fut_printf("[VFS-TEST] VFS correctness tests complete\n");
}

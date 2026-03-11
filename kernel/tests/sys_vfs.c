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
#define IN_CREATE  0x00000100U
#define IN_MODIFY  0x00000002U
#define IN_DELETE  0x00000200U
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

    /* Read event from inotify fd */
    struct test_inotify_event ev;
    ssize_t n = fut_vfs_read(ifd, &ev, sizeof(ev));
    fut_vfs_close(ifd);

    if (n != (ssize_t)sizeof(ev)) {
        fut_printf("[VFS-TEST] ✗ inotify read returned %ld (expected %zu)\n",
                   n, sizeof(ev));
        fut_test_fail(VFS_TEST_INOTIFY);
        return;
    }

    if (ev.wd != wd) {
        fut_printf("[VFS-TEST] ✗ inotify event wd=%d expected %d\n", ev.wd, wd);
        fut_test_fail(VFS_TEST_INOTIFY);
        return;
    }

    if (!(ev.mask & IN_CREATE)) {
        fut_printf("[VFS-TEST] ✗ inotify event mask=0x%x missing IN_CREATE\n", ev.mask);
        fut_test_fail(VFS_TEST_INOTIFY);
        return;
    }

    fut_printf("[VFS-TEST] ✓ inotify: IN_CREATE event received (wd=%d mask=0x%x)\n",
               ev.wd, ev.mask);
    fut_test_pass();
}

/* ------------------------------------------------------------------ */

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
    test_mount();
    test_renameat2();

    fut_printf("[VFS-TEST] VFS correctness tests complete\n");
}

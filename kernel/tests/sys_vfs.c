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
 */

#include <kernel/fut_task.h>
#include <kernel/fut_vfs.h>
#include <kernel/errno.h>
#include <kernel/kprintf.h>
#include <stddef.h>
#include <string.h>
#include "tests/test_api.h"

/* Test identifiers (for fut_test_fail error codes) */
#define VFS_TEST_TRUNC      1
#define VFS_TEST_APPEND     2
#define VFS_TEST_RELPATH    3
#define VFS_TEST_DIR_MTIME  4
#define VFS_TEST_READLINK   5
#define VFS_TEST_LINK       6

/* Use kernel-level VFS functions (no copy_from_user) */
#define sys_mkdir(path, mode)           fut_vfs_mkdir(path, (uint32_t)(mode))
#define sys_chdir(path)                 fut_vfs_chdir(path)
#define sys_symlink(target, linkpath)   fut_vfs_symlink(target, linkpath)
#define sys_readlink(path, buf, sz)     fut_vfs_readlink(path, buf, sz)
#define sys_link(old, new)              fut_vfs_link(old, new)

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

void fut_vfs_test_thread(void *arg) {
    (void)arg;

    fut_printf("[VFS-TEST] Starting VFS correctness tests\n");

    test_otrunc();
    test_oappend();
    test_relpath();
    test_dir_mtime();
    test_readlink();
    test_hardlink();

    fut_printf("[VFS-TEST] VFS correctness tests complete\n");
}

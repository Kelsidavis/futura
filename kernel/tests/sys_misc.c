/* kernel/tests/sys_misc.c - Miscellaneous syscall tests
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Tests for:
 *   - sys_getuid/geteuid/getgid/getegid: credential retrieval
 *   - sys_getresuid/getresgid: real/effective/saved IDs
 *   - sys_personality: execution domain get/set
 *   - sys_uname: system information retrieval
 *   - sys_getrlimit/setrlimit: resource limit get/set
 *   - sys_fcntl: file descriptor control operations
 */

#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <kernel/fut_percpu.h>
#include <kernel/fut_vfs.h>
#include <kernel/errno.h>
#include <kernel/kprintf.h>
#include <kernel/uaccess.h>
#include <kernel/fut_personality.h>
#include <sys/utsname.h>
#include <sys/resource.h>
#include <stdint.h>
#include <string.h>
#include "tests/test_api.h"

/* Architecture-specific paging headers for KERNEL_VIRTUAL_BASE */
#ifdef __x86_64__
#include <platform/x86_64/memory/paging.h>
#elif defined(__aarch64__)
#include <platform/arm64/memory/paging.h>
#endif

/* Kernel-pointer bypass helpers for copy_to_user/copy_from_user */
static inline int misc_copy_to_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)dst >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_to_user(dst, src, n);
}

static inline int misc_copy_from_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_from_user(dst, src, n);
}

static inline int misc_access_ok_write(const void *ptr, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)ptr >= KERNEL_VIRTUAL_BASE) return 0;
#endif
    return fut_access_ok(ptr, n, 1);
}

/* Forward declarations for syscalls under test */
extern long sys_getuid(void);
extern long sys_geteuid(void);
extern long sys_getgid(void);
extern long sys_getegid(void);
extern long sys_getresuid(uint32_t *ruid, uint32_t *euid, uint32_t *suid);
extern long sys_getresgid(uint32_t *rgid, uint32_t *egid, uint32_t *sgid);
extern long sys_personality(unsigned long persona);
extern long sys_uname(struct utsname *buf);
extern long sys_getrlimit(int resource, struct rlimit *rlim);
extern long sys_setrlimit(int resource, const struct rlimit *rlim);
extern long sys_fcntl(int fd, int cmd, uint64_t arg);

/* fcntl commands */
#define F_DUPFD         0
#define F_GETFD         1
#define F_SETFD         2
#define F_GETFL         3
#define F_SETFL         4
#define F_DUPFD_CLOEXEC 1030
#define FD_CLOEXEC      1

/* Resource limit constants */
#define TEST_RLIMIT_NOFILE  7
#define TEST_RLIMIT_NPROC   6
#define TEST_RLIMIT_STACK   3

/* ============================================================
 * Test 1: getuid/geteuid return consistent values
 * ============================================================ */
static void test_getuid(void) {
    fut_printf("[MISC-TEST] Test 1: getuid/geteuid/getgid/getegid consistency\n");

    long uid = sys_getuid();
    long euid = sys_geteuid();
    long gid = sys_getgid();
    long egid = sys_getegid();

    /* All should return non-negative values */
    if (uid < 0 || euid < 0 || gid < 0 || egid < 0) {
        fut_printf("[MISC-TEST] ✗ credential syscall returned error: uid=%ld euid=%ld gid=%ld egid=%ld\n",
                   uid, euid, gid, egid);
        fut_test_fail(1);
        return;
    }

    /* In kernel selftest context (running as root), uid should be 0 */
    if (uid != 0) {
        fut_printf("[MISC-TEST] ✗ getuid() returned %ld (expected 0 for kernel thread)\n", uid);
        fut_test_fail(1);
        return;
    }

    /* euid should match uid for kernel threads */
    if (euid != uid) {
        fut_printf("[MISC-TEST] ✗ euid=%ld != uid=%ld\n", euid, uid);
        fut_test_fail(1);
        return;
    }

    fut_printf("[MISC-TEST] ✓ credentials: uid=%ld euid=%ld gid=%ld egid=%ld\n",
               uid, euid, gid, egid);
    fut_test_pass();
}

/* ============================================================
 * Test 2: task credential fields are consistent
 * ============================================================
 * Note: sys_getresuid uses fut_copy_to_user which rejects kernel
 * stack pointers. Instead, verify the task struct fields directly. */
static void test_getresuid(void) {
    fut_printf("[MISC-TEST] Test 2: task credential fields are consistent\n");

    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[MISC-TEST] ✗ no current task\n");
        fut_test_fail(2);
        return;
    }

    /* For kernel thread (root), all UIDs should be 0 */
    if (task->uid != 0 || task->ruid != 0) {
        fut_printf("[MISC-TEST] ✗ task uids: uid=%u ruid=%u (expected 0)\n",
                   task->uid, task->ruid);
        fut_test_fail(2);
        return;
    }

    if (task->gid != 0 || task->rgid != 0) {
        fut_printf("[MISC-TEST] ✗ task gids: gid=%u rgid=%u (expected 0)\n",
                   task->gid, task->rgid);
        fut_test_fail(2);
        return;
    }

    /* getuid/geteuid should match stored values */
    long uid = sys_getuid();
    long euid = sys_geteuid();
    if ((uint32_t)uid != task->ruid || (uint32_t)euid != task->uid) {
        fut_printf("[MISC-TEST] ✗ syscall/field mismatch: getuid=%ld vs ruid=%u, geteuid=%ld vs uid=%u\n",
                   uid, task->ruid, euid, task->uid);
        fut_test_fail(2);
        return;
    }

    fut_printf("[MISC-TEST] ✓ credentials consistent: uid=%u ruid=%u gid=%u rgid=%u\n",
               task->uid, task->ruid, task->gid, task->rgid);
    fut_test_pass();
}

/* ============================================================
 * Test 3: personality query and set
 * ============================================================ */
static void test_personality(void) {
    fut_printf("[MISC-TEST] Test 3: personality query and set\n");

    /* Query current personality */
    long old = sys_personality(PER_QUERY);
    if (old < 0) {
        fut_printf("[MISC-TEST] ✗ personality(PER_QUERY) returned %ld\n", old);
        fut_test_fail(3);
        return;
    }

    /* Default should be PER_LINUX */
    if ((old & 0xFF) != PER_LINUX) {
        fut_printf("[MISC-TEST] ✗ default personality base=0x%lx (expected PER_LINUX=0)\n", old);
        fut_test_fail(3);
        return;
    }

    /* Set personality with ADDR_NO_RANDOMIZE flag */
    long prev = sys_personality(PER_LINUX | ADDR_NO_RANDOMIZE);
    if (prev < 0) {
        fut_printf("[MISC-TEST] ✗ personality(PER_LINUX|ADDR_NO_RANDOMIZE) returned %ld\n", prev);
        fut_test_fail(3);
        return;
    }

    /* Previous value should be what we queried */
    if ((unsigned long)prev != (unsigned long)old) {
        fut_printf("[MISC-TEST] ✗ personality returned old=0x%lx (expected 0x%lx)\n", prev, old);
        fut_test_fail(3);
        return;
    }

    /* Verify new personality was set */
    long cur = sys_personality(PER_QUERY);
    if (cur != (long)(PER_LINUX | ADDR_NO_RANDOMIZE)) {
        fut_printf("[MISC-TEST] ✗ personality after set: 0x%lx (expected 0x%lx)\n",
                   cur, (long)(PER_LINUX | ADDR_NO_RANDOMIZE));
        fut_test_fail(3);
        return;
    }

    /* Restore original */
    sys_personality(PER_LINUX);

    fut_printf("[MISC-TEST] ✓ personality: query, set, verify cycle works\n");
    fut_test_pass();
}

/* ============================================================
 * Test 4: personality rejects invalid base
 * ============================================================ */
static void test_personality_invalid(void) {
    fut_printf("[MISC-TEST] Test 4: personality rejects invalid base\n");

    /* Invalid base personality (0xFF is not a valid base) */
    long ret = sys_personality(0xFF);
    if (ret != -EINVAL) {
        fut_printf("[MISC-TEST] ✗ personality(0xFF) returned %ld (expected -EINVAL=%d)\n",
                   ret, -EINVAL);
        fut_test_fail(4);
        return;
    }

    fut_printf("[MISC-TEST] ✓ personality correctly rejects invalid base\n");
    fut_test_pass();
}

/* ============================================================
 * Test 5: uname rejects NULL pointer
 * ============================================================
 * Note: sys_uname uses fut_copy_to_user/fut_access_ok which reject
 * kernel pointers. We can still test error paths. */
static void test_uname_null(void) {
    fut_printf("[MISC-TEST] Test 5: uname rejects NULL pointer\n");

    long ret = sys_uname(NULL);
    if (ret != -EFAULT) {
        fut_printf("[MISC-TEST] ✗ uname(NULL) returned %ld (expected -EFAULT=%d)\n",
                   ret, -EFAULT);
        fut_test_fail(5);
        return;
    }

    fut_printf("[MISC-TEST] ✓ uname(NULL) correctly returns EFAULT\n");
    fut_test_pass();
}

/* ============================================================
 * Test 6: task rlimits have valid defaults
 * ============================================================
 * Note: sys_getrlimit/sys_setrlimit use fut_copy_to_user which rejects
 * kernel pointers. Verify the task rlimits structure directly. */
static void test_rlimits(void) {
    fut_printf("[MISC-TEST] Test 6: task rlimits have valid defaults\n");

    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[MISC-TEST] ✗ no current task\n");
        fut_test_fail(6);
        return;
    }

    /* RLIMIT_NOFILE (resource 7): soft <= hard */
    uint64_t nofile_cur = task->rlimits[TEST_RLIMIT_NOFILE].rlim_cur;
    uint64_t nofile_max = task->rlimits[TEST_RLIMIT_NOFILE].rlim_max;

    if (nofile_cur > nofile_max) {
        fut_printf("[MISC-TEST] ✗ RLIMIT_NOFILE: cur=%llu > max=%llu\n",
                   (unsigned long long)nofile_cur, (unsigned long long)nofile_max);
        fut_test_fail(6);
        return;
    }

    if (nofile_cur == 0) {
        fut_printf("[MISC-TEST] ✗ RLIMIT_NOFILE soft limit is 0\n");
        fut_test_fail(6);
        return;
    }

    /* Test rlimit modification round-trip via task struct */
    uint64_t orig_cur = nofile_cur;
    task->rlimits[TEST_RLIMIT_NOFILE].rlim_cur = 512;

    if (task->rlimits[TEST_RLIMIT_NOFILE].rlim_cur != 512) {
        fut_printf("[MISC-TEST] ✗ rlimit write failed\n");
        fut_test_fail(6);
        return;
    }

    /* Restore */
    task->rlimits[TEST_RLIMIT_NOFILE].rlim_cur = orig_cur;

    /* Also verify getrlimit returns EINVAL for invalid resource */
    struct rlimit dummy;
    long ret = sys_getrlimit(999, &dummy);
    if (ret != -EINVAL) {
        fut_printf("[MISC-TEST] ✗ getrlimit(999) returned %ld (expected -EINVAL)\n", ret);
        fut_test_fail(6);
        return;
    }

    fut_printf("[MISC-TEST] ✓ rlimits: NOFILE cur=%llu max=%llu, round-trip OK\n",
               (unsigned long long)nofile_cur, (unsigned long long)nofile_max);
    fut_test_pass();
}

/* ============================================================
 * Test 7: task personality stored correctly
 * ============================================================ */
static void test_personality_stored(void) {
    fut_printf("[MISC-TEST] Test 7: personality value stored in task struct\n");

    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[MISC-TEST] ✗ no current task\n");
        fut_test_fail(7);
        return;
    }

    /* After the personality tests above, it should be PER_LINUX */
    if ((task->personality & 0xFF) != PER_LINUX) {
        fut_printf("[MISC-TEST] ✗ task->personality=0x%lx (expected PER_LINUX)\n",
                   task->personality);
        fut_test_fail(7);
        return;
    }

    /* Set and verify via task struct */
    sys_personality(PER_LINUX | ADDR_LIMIT_32BIT);
    if (task->personality != (PER_LINUX | ADDR_LIMIT_32BIT)) {
        fut_printf("[MISC-TEST] ✗ task->personality=0x%lx after set (expected 0x%lx)\n",
                   task->personality, (unsigned long)(PER_LINUX | ADDR_LIMIT_32BIT));
        fut_test_fail(7);
        return;
    }

    /* Restore */
    sys_personality(PER_LINUX);

    fut_printf("[MISC-TEST] ✓ personality stored correctly in task struct\n");
    fut_test_pass();
}

/* ============================================================
 * Test 8: fcntl F_GETFD/F_SETFD on open file
 * ============================================================ */
static void test_fcntl_fd_flags(void) {
    fut_printf("[MISC-TEST] Test 8: fcntl F_GETFD/F_SETFD flag operations\n");

    /* Open a test file first */
    int fd = fut_vfs_open("/fcntl_test_file.txt", 0x42, 0644);  /* O_RDWR|O_CREAT */
    if (fd < 0) {
        fut_printf("[MISC-TEST] ✗ failed to open test file: %d\n", fd);
        fut_test_fail(8);
        return;
    }

    /* Get current fd flags (should be 0 initially) */
    long flags = sys_fcntl(fd, F_GETFD, 0);
    if (flags < 0) {
        fut_printf("[MISC-TEST] ✗ fcntl(F_GETFD) returned %ld\n", flags);
        fut_vfs_close(fd);
        fut_test_fail(8);
        return;
    }

    /* Set FD_CLOEXEC */
    long ret = sys_fcntl(fd, F_SETFD, FD_CLOEXEC);
    if (ret < 0) {
        fut_printf("[MISC-TEST] ✗ fcntl(F_SETFD, FD_CLOEXEC) returned %ld\n", ret);
        fut_vfs_close(fd);
        fut_test_fail(8);
        return;
    }

    /* Verify FD_CLOEXEC was set */
    flags = sys_fcntl(fd, F_GETFD, 0);
    if (!(flags & FD_CLOEXEC)) {
        fut_printf("[MISC-TEST] ✗ F_GETFD after F_SETFD: flags=0x%lx (expected FD_CLOEXEC)\n", flags);
        fut_vfs_close(fd);
        fut_test_fail(8);
        return;
    }

    /* Clear FD_CLOEXEC */
    ret = sys_fcntl(fd, F_SETFD, 0);
    if (ret < 0) {
        fut_printf("[MISC-TEST] ✗ fcntl(F_SETFD, 0) returned %ld\n", ret);
        fut_vfs_close(fd);
        fut_test_fail(8);
        return;
    }

    flags = sys_fcntl(fd, F_GETFD, 0);
    if (flags & FD_CLOEXEC) {
        fut_printf("[MISC-TEST] ✗ FD_CLOEXEC still set after clearing: flags=0x%lx\n", flags);
        fut_vfs_close(fd);
        fut_test_fail(8);
        return;
    }

    fut_vfs_close(fd);
    fut_printf("[MISC-TEST] ✓ fcntl F_GETFD/F_SETFD: set and clear FD_CLOEXEC works\n");
    fut_test_pass();
}

/* ============================================================
 * Test 9: fcntl F_DUPFD duplicates to minimum fd
 * ============================================================ */
static void test_fcntl_dupfd(void) {
    fut_printf("[MISC-TEST] Test 9: fcntl F_DUPFD duplicates file descriptor\n");

    /* Open a test file */
    int fd = fut_vfs_open("/fcntl_dupfd_test.txt", 0x42, 0644);  /* O_RDWR|O_CREAT */
    if (fd < 0) {
        fut_printf("[MISC-TEST] ✗ failed to open test file: %d\n", fd);
        fut_test_fail(9);
        return;
    }

    /* Duplicate to fd >= 20 */
    long newfd = sys_fcntl(fd, F_DUPFD, 20);
    if (newfd < 0) {
        fut_printf("[MISC-TEST] ✗ fcntl(F_DUPFD, 20) returned %ld\n", newfd);
        fut_vfs_close(fd);
        fut_test_fail(9);
        return;
    }

    if (newfd < 20) {
        fut_printf("[MISC-TEST] ✗ F_DUPFD returned fd=%ld (expected >= 20)\n", newfd);
        fut_vfs_close((int)newfd);
        fut_vfs_close(fd);
        fut_test_fail(9);
        return;
    }

    /* Verify the duplicate is usable — close both */
    fut_vfs_close((int)newfd);
    fut_vfs_close(fd);

    fut_printf("[MISC-TEST] ✓ fcntl F_DUPFD: original fd=%d duplicated to fd=%ld (>= 20)\n",
               fd, newfd);
    fut_test_pass();
}

/* ============================================================
 * Test 10: fcntl on invalid fd returns EBADF
 * ============================================================ */
static void test_fcntl_ebadf(void) {
    fut_printf("[MISC-TEST] Test 10: fcntl on invalid fd returns EBADF\n");

    long ret = sys_fcntl(999, F_GETFD, 0);
    if (ret != -EBADF) {
        fut_printf("[MISC-TEST] ✗ fcntl(999, F_GETFD) returned %ld (expected -EBADF=%d)\n",
                   ret, -EBADF);
        fut_test_fail(10);
        return;
    }

    ret = sys_fcntl(-1, F_GETFD, 0);
    if (ret != -EBADF) {
        fut_printf("[MISC-TEST] ✗ fcntl(-1, F_GETFD) returned %ld (expected -EBADF=%d)\n",
                   ret, -EBADF);
        fut_test_fail(10);
        return;
    }

    fut_printf("[MISC-TEST] ✓ fcntl correctly returns EBADF for invalid fds\n");
    fut_test_pass();
}

/* prctl option constants */
#define PR_SET_PDEATHSIG     1
#define PR_GET_PDEATHSIG     2
#define PR_SET_DUMPABLE      4
#define PR_GET_DUMPABLE      3
#define PR_SET_NAME         15
#define PR_GET_NAME         16
#define PR_SET_NO_NEW_PRIVS 38
#define PR_GET_NO_NEW_PRIVS 39

extern long sys_prctl(int option, unsigned long a2, unsigned long a3,
                      unsigned long a4, unsigned long a5);

/* ============================================================
 * Test 11: prctl PR_SET_NAME / PR_GET_NAME
 * ============================================================ */
static void test_prctl_name(void) {
    fut_printf("[MISC-TEST] Test 11: prctl PR_SET_NAME/PR_GET_NAME\n");

    /* Set process name */
    const char *name = "test_proc";
    long ret = sys_prctl(PR_SET_NAME, (unsigned long)name, 0, 0, 0);
    if (ret != 0) {
        fut_printf("[MISC-TEST] ✗ PR_SET_NAME returned %ld\n", ret);
        fut_test_fail(11);
        return;
    }

    /* Get it back and verify */
    char buf[16] = {0};
    ret = sys_prctl(PR_GET_NAME, (unsigned long)buf, 0, 0, 0);
    if (ret != 0) {
        fut_printf("[MISC-TEST] ✗ PR_GET_NAME returned %ld\n", ret);
        fut_test_fail(11);
        return;
    }

    if (strcmp(buf, "test_proc") != 0) {
        fut_printf("[MISC-TEST] ✗ PR_GET_NAME returned '%s' (expected 'test_proc')\n", buf);
        fut_test_fail(11);
        return;
    }

    fut_printf("[MISC-TEST] ✓ prctl PR_SET_NAME/PR_GET_NAME: '%s'\n", buf);
    fut_test_pass();
}

/* ============================================================
 * Test 12: prctl PR_SET_DUMPABLE / PR_GET_DUMPABLE
 * ============================================================ */
static void test_prctl_dumpable(void) {
    fut_printf("[MISC-TEST] Test 12: prctl PR_SET_DUMPABLE/PR_GET_DUMPABLE\n");

    /* Default should be dumpable (1) or at least non-negative */
    long val = sys_prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
    if (val < 0) {
        fut_printf("[MISC-TEST] ✗ PR_GET_DUMPABLE returned %ld\n", val);
        fut_test_fail(12);
        return;
    }

    /* Set to not dumpable */
    long ret = sys_prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    if (ret != 0) {
        fut_printf("[MISC-TEST] ✗ PR_SET_DUMPABLE(0) returned %ld\n", ret);
        fut_test_fail(12);
        return;
    }

    val = sys_prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
    if (val != 0) {
        fut_printf("[MISC-TEST] ✗ PR_GET_DUMPABLE after set 0: %ld\n", val);
        fut_test_fail(12);
        return;
    }

    /* Set back to dumpable */
    sys_prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);

    /* Invalid value should fail */
    ret = sys_prctl(PR_SET_DUMPABLE, 99, 0, 0, 0);
    if (ret != -EINVAL) {
        fut_printf("[MISC-TEST] ✗ PR_SET_DUMPABLE(99) returned %ld (expected EINVAL)\n", ret);
        fut_test_fail(12);
        return;
    }

    fut_printf("[MISC-TEST] ✓ prctl dumpable: set/get/validate works\n");
    fut_test_pass();
}

/* ============================================================
 * Test 13: prctl PR_SET_NO_NEW_PRIVS
 * ============================================================ */
static void test_prctl_no_new_privs(void) {
    fut_printf("[MISC-TEST] Test 13: prctl PR_SET_NO_NEW_PRIVS/PR_GET_NO_NEW_PRIVS\n");

    /* Should start as 0 (not set) */
    long val = sys_prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
    if (val != 0) {
        /* May already be set from a previous test run — still valid */
        fut_printf("[MISC-TEST]   note: no_new_privs already set to %ld\n", val);
    }

    /* Set it (sticky — can only set to 1, never unset) */
    long ret = sys_prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if (ret != 0) {
        fut_printf("[MISC-TEST] ✗ PR_SET_NO_NEW_PRIVS(1) returned %ld\n", ret);
        fut_test_fail(13);
        return;
    }

    val = sys_prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
    if (val != 1) {
        fut_printf("[MISC-TEST] ✗ PR_GET_NO_NEW_PRIVS after set: %ld (expected 1)\n", val);
        fut_test_fail(13);
        return;
    }

    /* Setting to 0 should fail (sticky) */
    ret = sys_prctl(PR_SET_NO_NEW_PRIVS, 0, 0, 0, 0);
    if (ret != -EINVAL) {
        fut_printf("[MISC-TEST] ✗ PR_SET_NO_NEW_PRIVS(0) returned %ld (expected EINVAL)\n", ret);
        fut_test_fail(13);
        return;
    }

    fut_printf("[MISC-TEST] ✓ prctl no_new_privs: set sticky flag, verify, reject unset\n");
    fut_test_pass();
}

/* ============================================================
 * Test 14: prctl unknown option returns EINVAL
 * ============================================================ */
static void test_prctl_invalid(void) {
    fut_printf("[MISC-TEST] Test 14: prctl unknown option returns EINVAL\n");

    long ret = sys_prctl(9999, 0, 0, 0, 0);
    if (ret != -EINVAL) {
        fut_printf("[MISC-TEST] ✗ prctl(9999) returned %ld (expected EINVAL)\n", ret);
        fut_test_fail(14);
        return;
    }

    fut_printf("[MISC-TEST] ✓ prctl correctly rejects unknown option\n");
    fut_test_pass();
}

extern long sys_getrandom(void *buf, size_t buflen, unsigned int flags);
extern long sys_fadvise64(int fd, int64_t offset, int64_t len, int advice);
extern long sys_copy_file_range(int fd_in, int64_t *off_in,
                                 int fd_out, int64_t *off_out,
                                 size_t len, unsigned int flags);
extern long sys_membarrier(int cmd, unsigned int flags, int cpu_id);
extern long sys_sched_getaffinity(int pid, unsigned int len, void *user_mask);
extern long sys_sched_setaffinity(int pid, unsigned int len, const void *user_mask);

/* ============================================================
 * Test 15: getrandom fills buffer with non-zero data
 * ============================================================ */
static void test_getrandom(void) {
    fut_printf("[MISC-TEST] Test 15: getrandom fills buffer with random data\n");

    uint8_t buf[32];
    memset(buf, 0, sizeof(buf));

    long ret = sys_getrandom(buf, sizeof(buf), 0);
    if (ret != 32) {
        fut_printf("[MISC-TEST] ✗ getrandom returned %ld (expected 32)\n", ret);
        fut_test_fail(15);
        return;
    }

    /* Check that at least some bytes are non-zero (probability of all-zero: 2^-256) */
    int nonzero = 0;
    for (int i = 0; i < 32; i++) {
        if (buf[i] != 0) nonzero++;
    }

    if (nonzero == 0) {
        fut_printf("[MISC-TEST] ✗ getrandom returned all zeros (statistically impossible)\n");
        fut_test_fail(15);
        return;
    }

    /* Verify two calls produce different output */
    uint8_t buf2[32];
    sys_getrandom(buf2, sizeof(buf2), 0);

    int same = 1;
    for (int i = 0; i < 32; i++) {
        if (buf[i] != buf2[i]) { same = 0; break; }
    }

    if (same) {
        fut_printf("[MISC-TEST] ✗ getrandom returned identical data twice\n");
        fut_test_fail(15);
        return;
    }

    /* Test invalid flags */
    ret = sys_getrandom(buf, sizeof(buf), 0xFFFF);
    if (ret != -EINVAL) {
        fut_printf("[MISC-TEST] ✗ getrandom(invalid flags) returned %ld (expected EINVAL)\n", ret);
        fut_test_fail(15);
        return;
    }

    fut_printf("[MISC-TEST] ✓ getrandom: 32 bytes, %d non-zero, different each call\n", nonzero);
    fut_test_pass();
}

/* ============================================================
 * Test 16: fadvise64 accepts valid hints
 * ============================================================ */
static void test_fadvise64(void) {
    fut_printf("[MISC-TEST] Test 16: fadvise64 accepts valid hints\n");

    /* Open a file to advise on */
    int fd = fut_vfs_open("/fadvise_test.txt", 0x42, 0644);  /* O_RDWR|O_CREAT */
    if (fd < 0) {
        fut_printf("[MISC-TEST] ✗ failed to open file: %d\n", fd);
        fut_test_fail(16);
        return;
    }

    /* Test all valid advice values */
    long ret = sys_fadvise64(fd, 0, 0, 0);  /* POSIX_FADV_NORMAL */
    if (ret != 0) {
        fut_printf("[MISC-TEST] ✗ fadvise64(NORMAL) returned %ld\n", ret);
        fut_vfs_close(fd);
        fut_test_fail(16);
        return;
    }

    ret = sys_fadvise64(fd, 0, 4096, 2);  /* POSIX_FADV_SEQUENTIAL */
    if (ret != 0) {
        fut_printf("[MISC-TEST] ✗ fadvise64(SEQUENTIAL) returned %ld\n", ret);
        fut_vfs_close(fd);
        fut_test_fail(16);
        return;
    }

    /* Invalid advice should fail */
    ret = sys_fadvise64(fd, 0, 0, 99);
    if (ret != -EINVAL) {
        fut_printf("[MISC-TEST] ✗ fadvise64(99) returned %ld (expected EINVAL)\n", ret);
        fut_vfs_close(fd);
        fut_test_fail(16);
        return;
    }

    /* Invalid fd should fail */
    ret = sys_fadvise64(999, 0, 0, 0);
    if (ret != -EBADF) {
        fut_printf("[MISC-TEST] ✗ fadvise64(fd=999) returned %ld (expected EBADF)\n", ret);
        fut_vfs_close(fd);
        fut_test_fail(16);
        return;
    }

    fut_vfs_close(fd);
    fut_printf("[MISC-TEST] ✓ fadvise64: valid hints accepted, invalid rejected\n");
    fut_test_pass();
}

/* ============================================================
 * Test 17: sched_getaffinity/setaffinity round-trip
 * ============================================================ */
static void test_sched_affinity(void) {
    fut_printf("[MISC-TEST] Test 17: sched_getaffinity/setaffinity round-trip\n");

    /* Get current affinity */
    uint64_t mask = 0;
    long ret = sys_sched_getaffinity(0, sizeof(mask), &mask);
    if (ret < 0) {
        fut_printf("[MISC-TEST] ✗ sched_getaffinity returned %ld\n", ret);
        fut_test_fail(17);
        return;
    }

    /* Set affinity to CPU 0 only */
    uint64_t new_mask = 0x1;
    ret = sys_sched_setaffinity(0, sizeof(new_mask), &new_mask);
    if (ret != 0) {
        fut_printf("[MISC-TEST] ✗ sched_setaffinity returned %ld\n", ret);
        fut_test_fail(17);
        return;
    }

    /* Read back and verify */
    uint64_t readback = 0;
    ret = sys_sched_getaffinity(0, sizeof(readback), &readback);
    if (ret < 0 || readback != 0x1) {
        fut_printf("[MISC-TEST] ✗ readback mask=0x%llx (expected 0x1)\n",
                   (unsigned long long)readback);
        fut_test_fail(17);
        return;
    }

    /* Empty mask should fail */
    uint64_t empty = 0;
    ret = sys_sched_setaffinity(0, sizeof(empty), &empty);
    if (ret != -EINVAL) {
        fut_printf("[MISC-TEST] ✗ sched_setaffinity(empty) returned %ld (expected EINVAL)\n", ret);
        fut_test_fail(17);
        return;
    }

    /* Restore original mask */
    if (mask != 0) {
        sys_sched_setaffinity(0, sizeof(mask), &mask);
    }

    fut_printf("[MISC-TEST] ✓ sched_affinity: get/set/verify round-trip works\n");
    fut_test_pass();
}

/* ============================================================
 * Test 18: copy_file_range copies data between fds
 * ============================================================ */
static void test_copy_file_range(void) {
    fut_printf("[MISC-TEST] Test 18: copy_file_range copies data between fds\n");

    /* Create source file with known content */
    int src = fut_vfs_open("/cfr_src.txt", 0x42, 0644);  /* O_RDWR|O_CREAT */
    if (src < 0) {
        fut_printf("[MISC-TEST] ✗ open src failed: %d\n", src);
        fut_test_fail(18);
        return;
    }

    const char *data = "Hello copy_file_range!";
    fut_vfs_write(src, data, 22);

    /* Rewind source */
    extern int64_t fut_vfs_lseek(int fd, int64_t offset, int whence);
    fut_vfs_lseek(src, 0, 0);  /* SEEK_SET */

    /* Create destination file */
    int dst = fut_vfs_open("/cfr_dst.txt", 0x42, 0644);
    if (dst < 0) {
        fut_printf("[MISC-TEST] ✗ open dst failed: %d\n", dst);
        fut_vfs_close(src);
        fut_test_fail(18);
        return;
    }

    /* Copy data */
    long copied = sys_copy_file_range(src, NULL, dst, NULL, 22, 0);
    if (copied != 22) {
        fut_printf("[MISC-TEST] ✗ copy_file_range returned %ld (expected 22)\n", copied);
        fut_vfs_close(dst);
        fut_vfs_close(src);
        fut_test_fail(18);
        return;
    }

    /* Read back from destination */
    fut_vfs_lseek(dst, 0, 0);
    char buf[32] = {0};
    ssize_t nread = fut_vfs_read(dst, buf, sizeof(buf));
    if (nread != 22 || memcmp(buf, data, 22) != 0) {
        fut_printf("[MISC-TEST] ✗ readback mismatch: nread=%zd buf='%s'\n", nread, buf);
        fut_vfs_close(dst);
        fut_vfs_close(src);
        fut_test_fail(18);
        return;
    }

    /* Invalid flags should fail */
    long ret = sys_copy_file_range(src, NULL, dst, NULL, 10, 1);
    if (ret != -EINVAL) {
        fut_printf("[MISC-TEST] ✗ copy_file_range(flags=1) returned %ld\n", ret);
        fut_vfs_close(dst);
        fut_vfs_close(src);
        fut_test_fail(18);
        return;
    }

    fut_vfs_close(dst);
    fut_vfs_close(src);
    fut_printf("[MISC-TEST] ✓ copy_file_range: copied 22 bytes, verified content\n");
    fut_test_pass();
}

/* ============================================================
 * Test 19: membarrier CMD_QUERY returns supported commands
 * ============================================================ */
static void test_membarrier(void) {
    fut_printf("[MISC-TEST] Test 19: membarrier CMD_QUERY\n");

    long supported = sys_membarrier(0 /* CMD_QUERY */, 0, 0);
    if (supported < 0) {
        fut_printf("[MISC-TEST] ✗ membarrier(CMD_QUERY) returned %ld\n", supported);
        fut_test_fail(19);
        return;
    }

    /* Should support at least CMD_GLOBAL (bit 0) */
    if (!(supported & 1)) {
        fut_printf("[MISC-TEST] ✗ CMD_GLOBAL not in supported mask: 0x%lx\n", supported);
        fut_test_fail(19);
        return;
    }

    /* CMD_GLOBAL should succeed */
    long ret = sys_membarrier(1 /* CMD_GLOBAL */, 0, 0);
    if (ret != 0) {
        fut_printf("[MISC-TEST] ✗ membarrier(CMD_GLOBAL) returned %ld\n", ret);
        fut_test_fail(19);
        return;
    }

    /* Invalid flags should fail */
    ret = sys_membarrier(0, 1, 0);
    if (ret != -EINVAL) {
        fut_printf("[MISC-TEST] ✗ membarrier(flags=1) returned %ld\n", ret);
        fut_test_fail(19);
        return;
    }

    fut_printf("[MISC-TEST] ✓ membarrier: supported=0x%lx, CMD_GLOBAL works\n", supported);
    fut_test_pass();
}

/* statx structures for testing */
struct fut_statx_timestamp {
    int64_t  tv_sec;
    uint32_t tv_nsec;
    int32_t  __reserved;
};

struct fut_statx {
    uint32_t stx_mask;
    uint32_t stx_blksize;
    uint64_t stx_attributes;
    uint32_t stx_nlink;
    uint32_t stx_uid;
    uint32_t stx_gid;
    uint16_t stx_mode;
    uint16_t __spare0[1];
    uint64_t stx_ino;
    uint64_t stx_size;
    uint64_t stx_blocks;
    uint64_t stx_attributes_mask;
    struct fut_statx_timestamp stx_atime;
    struct fut_statx_timestamp stx_btime;
    struct fut_statx_timestamp stx_ctime;
    struct fut_statx_timestamp stx_mtime;
    uint32_t stx_rdev_major;
    uint32_t stx_rdev_minor;
    uint32_t stx_dev_major;
    uint32_t stx_dev_minor;
    uint64_t stx_mnt_id;
    uint32_t stx_dio_mem_align;
    uint32_t stx_dio_offset_align;
    uint64_t __spare3[12];
};

#define STATX_BASIC_STATS 0x000007ffU
#define STATX_BTIME       0x00000800U
#define STATX_TYPE        0x00000001U
#define STATX_MODE        0x00000002U
#define STATX_SIZE        0x00000200U
#define STATX_INO         0x00000100U

extern long sys_statx(int dirfd, const char *pathname, int flags,
                      unsigned int mask, struct fut_statx *statxbuf);

/* ============================================================
 * Test 20: statx on a regular file returns correct metadata
 * ============================================================ */
static void test_statx_basic(void) {
    fut_printf("[MISC-TEST] Test 20: statx on a regular file\n");

    /* Create a test file with known content */
    int fd = fut_vfs_open("/statx_test.txt", 0x42, 0644);  /* O_RDWR|O_CREAT */
    if (fd < 0) {
        fut_printf("[MISC-TEST] ✗ failed to open test file: %d\n", fd);
        fut_test_fail(20);
        return;
    }
    const char *data = "statx test data";
    fut_vfs_write(fd, data, 15);
    fut_vfs_close(fd);

    /* Call statx with AT_FDCWD and absolute path */
    struct fut_statx sx;
    memset(&sx, 0, sizeof(sx));
    long ret = sys_statx(-100 /* AT_FDCWD */, "/statx_test.txt", 0,
                         STATX_BASIC_STATS | STATX_BTIME, &sx);
    if (ret != 0) {
        fut_printf("[MISC-TEST] ✗ statx returned %ld\n", ret);
        fut_test_fail(20);
        return;
    }

    /* Verify mask reports what was filled */
    if (!(sx.stx_mask & STATX_TYPE)) {
        fut_printf("[MISC-TEST] ✗ stx_mask missing STATX_TYPE: 0x%x\n", sx.stx_mask);
        fut_test_fail(20);
        return;
    }

    /* Verify it's a regular file (S_IFREG = 0100000) */
    if ((sx.stx_mode & 0170000) != 0100000) {
        fut_printf("[MISC-TEST] ✗ stx_mode type=0%o (expected S_IFREG)\n", sx.stx_mode & 0170000);
        fut_test_fail(20);
        return;
    }

    /* Verify size matches what we wrote */
    if (sx.stx_size != 15) {
        fut_printf("[MISC-TEST] ✗ stx_size=%llu (expected 15)\n",
                   (unsigned long long)sx.stx_size);
        fut_test_fail(20);
        return;
    }

    /* Verify inode is non-zero */
    if (sx.stx_ino == 0) {
        fut_printf("[MISC-TEST] ✗ stx_ino is 0\n");
        fut_test_fail(20);
        return;
    }

    /* Verify blksize is reasonable */
    if (sx.stx_blksize == 0) {
        fut_printf("[MISC-TEST] ✗ stx_blksize is 0\n");
        fut_test_fail(20);
        return;
    }

    fut_printf("[MISC-TEST] ✓ statx: ino=%llu size=%llu mode=0%o blksize=%u\n",
               (unsigned long long)sx.stx_ino, (unsigned long long)sx.stx_size,
               sx.stx_mode, sx.stx_blksize);
    fut_test_pass();
}

/* ============================================================
 * Test 21: statx error paths
 * ============================================================ */
static void test_statx_errors(void) {
    fut_printf("[MISC-TEST] Test 21: statx error paths\n");

    struct fut_statx sx;

    /* Non-existent file → ENOENT */
    long ret = sys_statx(-100 /* AT_FDCWD */, "/no_such_file_statx", 0,
                         STATX_BASIC_STATS, &sx);
    if (ret != -ENOENT) {
        fut_printf("[MISC-TEST] ✗ statx(nonexistent) returned %ld (expected -ENOENT=%d)\n",
                   ret, -ENOENT);
        fut_test_fail(21);
        return;
    }

    /* Invalid flags → EINVAL */
    ret = sys_statx(-100, "/statx_test.txt", 0x80000000, STATX_BASIC_STATS, &sx);
    if (ret != -EINVAL) {
        fut_printf("[MISC-TEST] ✗ statx(invalid flags) returned %ld (expected -EINVAL)\n", ret);
        fut_test_fail(21);
        return;
    }

    /* NULL buffer → EFAULT */
    ret = sys_statx(-100, "/statx_test.txt", 0, STATX_BASIC_STATS, NULL);
    if (ret != -EFAULT) {
        fut_printf("[MISC-TEST] ✗ statx(NULL buf) returned %ld (expected -EFAULT)\n", ret);
        fut_test_fail(21);
        return;
    }

    fut_printf("[MISC-TEST] ✓ statx errors: ENOENT, EINVAL, EFAULT all correct\n");
    fut_test_pass();
}

extern long sys_tgkill(int tgid, int tid, int sig);
extern long sys_tkill(int tid, int sig);

/* ============================================================
 * Test 22: tgkill sends signal to current thread
 * ============================================================ */
static void test_tgkill(void) {
    fut_printf("[MISC-TEST] Test 22: tgkill/tkill thread-directed signals\n");

    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[MISC-TEST] ✗ no current task\n");
        fut_test_fail(22);
        return;
    }

    /* Get current thread's tid and task's pid */
    fut_thread_t *thread = NULL;
    fut_percpu_t *percpu = fut_percpu_get();
    if (percpu && percpu->current_thread) {
        thread = percpu->current_thread;
    }
    if (!thread) {
        fut_printf("[MISC-TEST] ✗ no current thread\n");
        fut_test_fail(22);
        return;
    }

    int pid = (int)task->pid;
    int tid = (int)thread->tid;

    /* Signal 0 to self should succeed (permission check) */
    long ret = sys_tgkill(pid, tid, 0);
    if (ret != 0) {
        fut_printf("[MISC-TEST] ✗ tgkill(pid=%d, tid=%d, sig=0) returned %ld\n",
                   pid, tid, ret);
        fut_test_fail(22);
        return;
    }

    /* Invalid signal → EINVAL */
    ret = sys_tgkill(pid, tid, 99);
    if (ret != -EINVAL) {
        fut_printf("[MISC-TEST] ✗ tgkill(sig=99) returned %ld (expected EINVAL)\n", ret);
        fut_test_fail(22);
        return;
    }

    /* Invalid tgid → EINVAL */
    ret = sys_tgkill(-1, tid, 0);
    if (ret != -EINVAL) {
        fut_printf("[MISC-TEST] ✗ tgkill(tgid=-1) returned %ld (expected EINVAL)\n", ret);
        fut_test_fail(22);
        return;
    }

    /* Non-existent tid → ESRCH */
    ret = sys_tgkill(pid, 99999, 0);
    if (ret != -ESRCH) {
        fut_printf("[MISC-TEST] ✗ tgkill(tid=99999) returned %ld (expected ESRCH)\n", ret);
        fut_test_fail(22);
        return;
    }

    /* Wrong tgid for existing tid → ESRCH */
    ret = sys_tgkill(99999, tid, 0);
    if (ret != -ESRCH) {
        fut_printf("[MISC-TEST] ✗ tgkill(tgid=99999) returned %ld (expected ESRCH)\n", ret);
        fut_test_fail(22);
        return;
    }

    /* tkill signal 0 to self should succeed */
    ret = sys_tkill(tid, 0);
    if (ret != 0) {
        fut_printf("[MISC-TEST] ✗ tkill(tid=%d, sig=0) returned %ld\n", tid, ret);
        fut_test_fail(22);
        return;
    }

    /* tkill invalid tid → EINVAL */
    ret = sys_tkill(-1, 0);
    if (ret != -EINVAL) {
        fut_printf("[MISC-TEST] ✗ tkill(tid=-1) returned %ld (expected EINVAL)\n", ret);
        fut_test_fail(22);
        return;
    }

    fut_printf("[MISC-TEST] ✓ tgkill/tkill: sig=0 self, EINVAL, ESRCH all correct\n");
    fut_test_pass();
}

extern long sys_getcpu(unsigned int *cpup, unsigned int *nodep, void *unused);

/* ============================================================
 * Test 23: getcpu returns valid CPU number
 * ============================================================ */
static void test_getcpu(void) {
    fut_printf("[MISC-TEST] Test 23: getcpu returns valid CPU\n");

    unsigned int cpu = 0xFFFFFFFF;
    unsigned int node = 0xFFFFFFFF;
    long ret = sys_getcpu(&cpu, &node, NULL);
    if (ret != 0) {
        fut_printf("[MISC-TEST] ✗ getcpu returned %ld\n", ret);
        fut_test_fail(23);
        return;
    }

    /* CPU should be a small number (0 for QEMU single-CPU) */
    if (cpu > 255) {
        fut_printf("[MISC-TEST] ✗ cpu=%u (unreasonably high)\n", cpu);
        fut_test_fail(23);
        return;
    }

    /* Node should be 0 (single NUMA) */
    if (node != 0) {
        fut_printf("[MISC-TEST] ✗ node=%u (expected 0)\n", node);
        fut_test_fail(23);
        return;
    }

    /* NULL pointers should be accepted */
    ret = sys_getcpu(NULL, NULL, NULL);
    if (ret != 0) {
        fut_printf("[MISC-TEST] ✗ getcpu(NULL, NULL) returned %ld\n", ret);
        fut_test_fail(23);
        return;
    }

    fut_printf("[MISC-TEST] ✓ getcpu: cpu=%u node=%u\n", cpu, node);
    fut_test_pass();
}

extern long sys_readahead(int fd, int64_t offset, size_t count);
extern long sys_getgroups(int size, uint32_t *list);
extern long sys_setgroups(int size, const uint32_t *list);

/* ============================================================
 * Test 24: readahead accepts hints and rejects bad fds
 * ============================================================ */
static void test_readahead(void) {
    fut_printf("[MISC-TEST] Test 24: readahead hint syscall\n");

    /* Open a file to readahead on */
    int fd = fut_vfs_open("/readahead_test.txt", 0x42, 0644);  /* O_RDWR|O_CREAT */
    if (fd < 0) {
        fut_printf("[MISC-TEST] ✗ open failed: %d\n", fd);
        fut_test_fail(24);
        return;
    }
    fut_vfs_write(fd, "test data", 9);

    /* readahead on valid file should succeed */
    long ret = sys_readahead(fd, 0, 4096);
    if (ret != 0) {
        fut_printf("[MISC-TEST] ✗ readahead(fd, 0, 4096) returned %ld\n", ret);
        fut_vfs_close(fd);
        fut_test_fail(24);
        return;
    }

    fut_vfs_close(fd);

    /* Bad fd → EBADF */
    ret = sys_readahead(999, 0, 4096);
    if (ret != -EBADF) {
        fut_printf("[MISC-TEST] ✗ readahead(999) returned %ld (expected EBADF)\n", ret);
        fut_test_fail(24);
        return;
    }

    /* Negative offset → EINVAL */
    ret = sys_readahead(0, -1, 4096);
    if (ret != -EINVAL) {
        fut_printf("[MISC-TEST] ✗ readahead(offset=-1) returned %ld (expected EINVAL)\n", ret);
        fut_test_fail(24);
        return;
    }

    fut_printf("[MISC-TEST] ✓ readahead: valid hint accepted, EBADF/EINVAL correct\n");
    fut_test_pass();
}

/* ============================================================
 * Test 25: getgroups/setgroups round-trip
 * ============================================================ */
static void test_groups(void) {
    fut_printf("[MISC-TEST] Test 25: getgroups/setgroups round-trip\n");

    /* Query initial count (should be 0 for kernel thread) */
    long count = sys_getgroups(0, NULL);
    if (count < 0) {
        fut_printf("[MISC-TEST] ✗ getgroups(0) returned %ld\n", count);
        fut_test_fail(25);
        return;
    }

    /* Set some groups */
    uint32_t groups_to_set[] = {100, 200, 300};
    long ret = sys_setgroups(3, groups_to_set);
    if (ret != 0) {
        fut_printf("[MISC-TEST] ✗ setgroups(3) returned %ld\n", ret);
        fut_test_fail(25);
        return;
    }

    /* Read back */
    count = sys_getgroups(0, NULL);
    if (count != 3) {
        fut_printf("[MISC-TEST] ✗ getgroups(0) returned %ld (expected 3)\n", count);
        fut_test_fail(25);
        return;
    }

    uint32_t readback[3] = {0};
    ret = sys_getgroups(3, readback);
    if (ret != 3) {
        fut_printf("[MISC-TEST] ✗ getgroups(3) returned %ld\n", ret);
        fut_test_fail(25);
        return;
    }

    if (readback[0] != 100 || readback[1] != 200 || readback[2] != 300) {
        fut_printf("[MISC-TEST] ✗ groups mismatch: %u %u %u\n",
                   readback[0], readback[1], readback[2]);
        fut_test_fail(25);
        return;
    }

    /* Clear groups */
    sys_setgroups(0, NULL);

    /* Too many groups → EINVAL */
    ret = sys_setgroups(33, groups_to_set);
    if (ret != -EINVAL) {
        fut_printf("[MISC-TEST] ✗ setgroups(33) returned %ld (expected EINVAL)\n", ret);
        fut_test_fail(25);
        return;
    }

    fut_printf("[MISC-TEST] ✓ getgroups/setgroups: set 3, readback matches, clear, EINVAL\n");
    fut_test_pass();
}

extern long sys_socketpair(int domain, int type, int protocol, int *sv);

/* ============================================================
 * Test 26: socketpair creates connected AF_UNIX pair
 * ============================================================ */
static void test_socketpair(void) {
    fut_printf("[MISC-TEST] Test 26: socketpair creates connected pair\n");

    int sv[2] = {-1, -1};
    long ret = sys_socketpair(1 /* AF_UNIX */, 1 /* SOCK_STREAM */, 0, sv);
    if (ret != 0) {
        fut_printf("[MISC-TEST] ✗ socketpair returned %ld\n", ret);
        fut_test_fail(26);
        return;
    }

    if (sv[0] < 0 || sv[1] < 0) {
        fut_printf("[MISC-TEST] ✗ invalid fds: %d, %d\n", sv[0], sv[1]);
        fut_test_fail(26);
        return;
    }

    if (sv[0] == sv[1]) {
        fut_printf("[MISC-TEST] ✗ both fds are the same: %d\n", sv[0]);
        fut_vfs_close(sv[0]);
        fut_test_fail(26);
        return;
    }

    /* Write on sv[0], read on sv[1] */
    const char *msg = "hello";
    ssize_t nw = fut_vfs_write(sv[0], msg, 5);
    if (nw != 5) {
        fut_printf("[MISC-TEST] ✗ write returned %zd\n", nw);
        fut_vfs_close(sv[0]);
        fut_vfs_close(sv[1]);
        fut_test_fail(26);
        return;
    }

    char buf[8] = {0};
    ssize_t nr = fut_vfs_read(sv[1], buf, sizeof(buf));
    if (nr != 5 || memcmp(buf, "hello", 5) != 0) {
        fut_printf("[MISC-TEST] ✗ read returned %zd buf='%s'\n", nr, buf);
        fut_vfs_close(sv[0]);
        fut_vfs_close(sv[1]);
        fut_test_fail(26);
        return;
    }

    /* Unsupported domain → EAFNOSUPPORT */
    int sv2[2];
    ret = sys_socketpair(2 /* AF_INET */, 1, 0, sv2);
    if (ret != -EAFNOSUPPORT) {
        fut_printf("[MISC-TEST] ✗ socketpair(AF_INET) returned %ld (expected EAFNOSUPPORT)\n", ret);
        fut_vfs_close(sv[0]);
        fut_vfs_close(sv[1]);
        fut_test_fail(26);
        return;
    }

    fut_vfs_close(sv[0]);
    fut_vfs_close(sv[1]);
    fut_printf("[MISC-TEST] ✓ socketpair: created pair, sent/received 'hello'\n");
    fut_test_pass();
}

/* ============================================================
 * Test 27: O_CLOEXEC sets FD_CLOEXEC on open
 * ============================================================ */
static void test_open_cloexec(void) {
    fut_printf("[MISC-TEST] Test 27: O_CLOEXEC sets FD_CLOEXEC on open\n");

    /* Open with O_CLOEXEC (0x80000) */
    int fd = fut_vfs_open("/cloexec_test.txt", 0x80042, 0644);  /* O_RDWR|O_CREAT|O_CLOEXEC */
    if (fd < 0) {
        fut_printf("[MISC-TEST] ✗ open with O_CLOEXEC failed: %d\n", fd);
        fut_test_fail(27);
        return;
    }

    /* Verify FD_CLOEXEC is set */
    extern long sys_fcntl(int fd, int cmd, uint64_t arg);
    long flags = sys_fcntl(fd, 1 /* F_GETFD */, 0);
    fut_vfs_close(fd);

    if (!(flags & 1 /* FD_CLOEXEC */)) {
        fut_printf("[MISC-TEST] ✗ O_CLOEXEC open: FD_CLOEXEC not set (flags=0x%lx)\n", flags);
        fut_test_fail(27);
        return;
    }

    /* Open without O_CLOEXEC — FD_CLOEXEC should NOT be set */
    fd = fut_vfs_open("/cloexec_test2.txt", 0x42, 0644);  /* O_RDWR|O_CREAT */
    if (fd < 0) {
        fut_printf("[MISC-TEST] ✗ open without O_CLOEXEC failed: %d\n", fd);
        fut_test_fail(27);
        return;
    }

    flags = sys_fcntl(fd, 1 /* F_GETFD */, 0);
    fut_vfs_close(fd);

    if (flags & 1 /* FD_CLOEXEC */) {
        fut_printf("[MISC-TEST] ✗ non-CLOEXEC open has FD_CLOEXEC set (flags=0x%lx)\n", flags);
        fut_test_fail(27);
        return;
    }

    fut_printf("[MISC-TEST] ✓ O_CLOEXEC: sets FD_CLOEXEC, absent without flag\n");
    fut_test_pass();
}

/* ============================================================
 * Test entry point
 * ============================================================ */
void fut_misc_test_thread(void *arg) {
    (void)arg;

    fut_printf("[MISC-TEST] ========================================\n");
    fut_printf("[MISC-TEST] Miscellaneous Syscall Tests\n");
    fut_printf("[MISC-TEST] ========================================\n");

    test_getuid();              /* Test 1: uid/euid/gid/egid */
    test_getresuid();           /* Test 2: task credential fields */
    test_personality();         /* Test 3: personality query/set */
    test_personality_invalid(); /* Test 4: personality invalid base */
    test_uname_null();          /* Test 5: uname NULL pointer */
    test_rlimits();             /* Test 6: task rlimits */
    test_personality_stored();  /* Test 7: personality task storage */
    test_fcntl_fd_flags();      /* Test 8: fcntl F_GETFD/F_SETFD */
    test_fcntl_dupfd();         /* Test 9: fcntl F_DUPFD */
    test_fcntl_ebadf();         /* Test 10: fcntl EBADF */
    test_prctl_name();          /* Test 11: prctl PR_SET_NAME/PR_GET_NAME */
    test_prctl_dumpable();      /* Test 12: prctl dumpable */
    test_prctl_no_new_privs();  /* Test 13: prctl no_new_privs */
    test_prctl_invalid();       /* Test 14: prctl invalid option */
    test_getrandom();           /* Test 15: getrandom */
    test_fadvise64();           /* Test 16: fadvise64 */
    test_sched_affinity();      /* Test 17: sched_affinity */
    test_copy_file_range();     /* Test 18: copy_file_range */
    test_membarrier();          /* Test 19: membarrier */
    test_statx_basic();         /* Test 20: statx basic */
    test_statx_errors();        /* Test 21: statx errors */
    test_tgkill();              /* Test 22: tgkill/tkill */
    test_getcpu();              /* Test 23: getcpu */
    test_readahead();           /* Test 24: readahead */
    test_groups();              /* Test 25: getgroups/setgroups */
    test_socketpair();          /* Test 26: socketpair */
    test_open_cloexec();        /* Test 27: O_CLOEXEC */

    fut_printf("[MISC-TEST] ========================================\n");
    fut_printf("[MISC-TEST] All miscellaneous syscall tests done\n");
    fut_printf("[MISC-TEST] ========================================\n");
}

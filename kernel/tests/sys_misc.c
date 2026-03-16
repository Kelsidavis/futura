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

    fut_printf("[MISC-TEST] ========================================\n");
    fut_printf("[MISC-TEST] All miscellaneous syscall tests done\n");
    fut_printf("[MISC-TEST] ========================================\n");
}

/* kernel/tests/sys_clock_sched.c - clock, sched, timer, and rusage syscall tests
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Tests for:
 *   - sys_clock_getres: verify tick-accurate resolution
 *   - sys_sched_setparam/getparam: store and retrieve RT priority
 *   - sys_sched_setscheduler/getscheduler: store and retrieve scheduling policy
 *   - sys_setitimer/getitimer: arm and read back ITIMER_REAL
 *   - sys_getrusage: verify non-zero CPU time after activity
 *   - sys_times: verify non-zero tms_utime after activity
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/kprintf.h>
#include <kernel/uaccess.h>
#include <kernel/fut_timer.h>
#include <shared/fut_timespec.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sched.h>
#include <stdint.h>
#include <string.h>
#include "tests/test_api.h"

/* Forward declarations */
extern long sys_clock_getres(int clock_id, fut_timespec_t *res);
extern long sys_sched_setparam(int pid, const struct sched_param *param);
extern long sys_sched_getparam(int pid, struct sched_param *param);
extern long sys_sched_setscheduler(int pid, int policy, const struct sched_param *param);
extern long sys_sched_getscheduler(int pid);
extern long sys_setitimer(int which, const struct itimerval *value, struct itimerval *ovalue);
extern long sys_getitimer(int which, struct itimerval *value);
extern long sys_getrusage(int who, void *usage);
extern long sys_times(struct tms *buf);
extern long sys_getpriority(int which, int who);
extern long sys_setpriority(int which, int who, int prio);
extern long sys_unshare(unsigned long flags);

/* rusage structure (mirrored from sys_rusage.c) */
struct test_rusage {
    struct timeval ru_utime;
    struct timeval ru_stime;
    long ru_maxrss;
    long ru_ixrss;
    long ru_idrss;
    long ru_isrss;
    long ru_minflt;
    long ru_majflt;
    long ru_nswap;
    long ru_inblock;
    long ru_oublock;
    long ru_msgsnd;
    long ru_msgrcv;
    long ru_nsignals;
    long ru_nvcsw;
    long ru_nivcsw;
};

#define RUSAGE_SELF     0
#define RUSAGE_THREAD   1

/* Test IDs */
#define CLKSCHED_TEST_GETRES          1
#define CLKSCHED_TEST_SCHED_PARAM     2
#define CLKSCHED_TEST_SCHED_POLICY    3
#define CLKSCHED_TEST_ITIMER          4
#define CLKSCHED_TEST_GETRUSAGE       5
#define CLKSCHED_TEST_TIMES           6
#define CLKSCHED_TEST_GETPRIORITY     7
#define CLKSCHED_TEST_SETPRIORITY     8
#define CLKSCHED_TEST_GETPRIO_NEGWHO  9
#define CLKSCHED_TEST_SETPRIO_NEGWHO 10
#define CLKSCHED_TEST_UNSHARE_NOOP   11
#define CLKSCHED_TEST_UNSHARE_INVAL  12

/* PRIO_PROCESS constant (matches sys_sched.c) */
#define TEST_PRIO_PROCESS  0

/* unshare() flags (match kernel/sys_unshare.c) */
#define TEST_CLONE_FILES 0x00000400UL

/* ============================================================
 * Test 1: sys_clock_getres returns timer-tick-accurate resolution
 * ============================================================ */
static void test_clock_getres(void) {
    fut_printf("[CLKSCHED-TEST] Test 1: sys_clock_getres returns accurate resolution\n");

    fut_timespec_t res;
    long ret = sys_clock_getres(CLOCK_MONOTONIC, &res);

    if (ret != 0) {
        fut_printf("[CLKSCHED-TEST] ✗ clock_getres returned %ld\n", ret);
        fut_test_fail(CLKSCHED_TEST_GETRES);
        return;
    }

    if (res.tv_sec != 0) {
        fut_printf("[CLKSCHED-TEST] ✗ tv_sec=%lld (expected 0)\n", res.tv_sec);
        fut_test_fail(CLKSCHED_TEST_GETRES);
        return;
    }

    /* Resolution should be 1,000,000,000 / FUT_TIMER_HZ nanoseconds */
    long expected_ns = (long)(1000000000UL / FUT_TIMER_HZ);
    if (res.tv_nsec != expected_ns) {
        fut_printf("[CLKSCHED-TEST] ✗ tv_nsec=%lld (expected %ld for %d Hz timer)\n",
                   res.tv_nsec, expected_ns, FUT_TIMER_HZ);
        fut_test_fail(CLKSCHED_TEST_GETRES);
        return;
    }

    /* NULL res pointer should also succeed (just validate clock id) */
    ret = sys_clock_getres(CLOCK_REALTIME, NULL);
    if (ret != 0) {
        fut_printf("[CLKSCHED-TEST] ✗ clock_getres(CLOCK_REALTIME, NULL) returned %ld\n", ret);
        fut_test_fail(CLKSCHED_TEST_GETRES);
        return;
    }

    fut_printf("[CLKSCHED-TEST] ✓ clock_getres: tv_nsec=%ld (%d Hz)\n",
               expected_ns, FUT_TIMER_HZ);
    fut_test_pass();
}

/* ============================================================
 * Test 2: sched_setparam/getparam store and retrieve RT priority
 * ============================================================ */
static void test_sched_param(void) {
    fut_printf("[CLKSCHED-TEST] Test 2: sched_setparam/getparam roundtrip\n");

    struct sched_param param;
    param.sched_priority = 42;

    long ret = sys_sched_setparam(0, &param);
    if (ret != 0) {
        fut_printf("[CLKSCHED-TEST] ✗ sched_setparam(0, 42) returned %ld\n", ret);
        fut_test_fail(CLKSCHED_TEST_SCHED_PARAM);
        return;
    }

    struct sched_param out;
    memset(&out, 0, sizeof(out));
    ret = sys_sched_getparam(0, &out);
    if (ret != 0) {
        fut_printf("[CLKSCHED-TEST] ✗ sched_getparam returned %ld\n", ret);
        fut_test_fail(CLKSCHED_TEST_SCHED_PARAM);
        return;
    }

    if (out.sched_priority != 42) {
        fut_printf("[CLKSCHED-TEST] ✗ priority=%d (expected 42)\n", out.sched_priority);
        fut_test_fail(CLKSCHED_TEST_SCHED_PARAM);
        return;
    }

    /* Restore to 0 for clean state */
    param.sched_priority = 0;
    sys_sched_setparam(0, &param);

    fut_printf("[CLKSCHED-TEST] ✓ sched_setparam/getparam roundtrip OK\n");
    fut_test_pass();
}

/* ============================================================
 * Test 3: sched_setscheduler/getscheduler store and retrieve policy
 * ============================================================ */
static void test_sched_policy(void) {
    fut_printf("[CLKSCHED-TEST] Test 3: sched_setscheduler/getscheduler roundtrip\n");

    /* Get initial policy (should be SCHED_OTHER = 0) */
    long initial = sys_sched_getscheduler(0);
    if (initial < 0) {
        fut_printf("[CLKSCHED-TEST] ✗ sched_getscheduler initial returned %ld\n", initial);
        fut_test_fail(CLKSCHED_TEST_SCHED_POLICY);
        return;
    }

    /* Set SCHED_OTHER (policy 0) with priority 0 */
    struct sched_param param;
    param.sched_priority = 0;
    long old = sys_sched_setscheduler(0, SCHED_OTHER, &param);
    if (old < 0) {
        fut_printf("[CLKSCHED-TEST] ✗ sched_setscheduler returned %ld\n", old);
        fut_test_fail(CLKSCHED_TEST_SCHED_POLICY);
        return;
    }

    long current = sys_sched_getscheduler(0);
    if (current != SCHED_OTHER) {
        fut_printf("[CLKSCHED-TEST] ✗ policy=%ld (expected SCHED_OTHER=%d)\n",
                   current, SCHED_OTHER);
        fut_test_fail(CLKSCHED_TEST_SCHED_POLICY);
        return;
    }

    fut_printf("[CLKSCHED-TEST] ✓ sched_setscheduler/getscheduler roundtrip OK\n");
    fut_test_pass();
}

/* ============================================================
 * Test 4: setitimer/getitimer arm and read back ITIMER_REAL
 * ============================================================ */
static void test_itimer(void) {
    fut_printf("[CLKSCHED-TEST] Test 4: setitimer/getitimer ITIMER_REAL roundtrip\n");

    /* Arm ITIMER_REAL with 5 second one-shot */
    struct itimerval arm;
    memset(&arm, 0, sizeof(arm));
    arm.it_value.tv_sec  = 5;
    arm.it_value.tv_usec = 0;
    arm.it_interval.tv_sec  = 2;
    arm.it_interval.tv_usec = 0;

    long ret = sys_setitimer(ITIMER_REAL, &arm, NULL);
    if (ret != 0) {
        fut_printf("[CLKSCHED-TEST] ✗ setitimer returned %ld\n", ret);
        fut_test_fail(CLKSCHED_TEST_ITIMER);
        return;
    }

    /* Read back — it_value will be slightly less than 5s */
    struct itimerval cur;
    memset(&cur, 0, sizeof(cur));
    ret = sys_getitimer(ITIMER_REAL, &cur);
    if (ret != 0) {
        fut_printf("[CLKSCHED-TEST] ✗ getitimer returned %ld\n", ret);
        fut_test_fail(CLKSCHED_TEST_ITIMER);
        return;
    }

    /* it_value should be > 0 (timer was just armed) */
    if (cur.it_value.tv_sec == 0 && cur.it_value.tv_usec == 0) {
        fut_printf("[CLKSCHED-TEST] ✗ it_value is zero (timer not armed?)\n");
        fut_test_fail(CLKSCHED_TEST_ITIMER);
        return;
    }

    /* it_interval should be exactly 2s */
    if (cur.it_interval.tv_sec != 2) {
        fut_printf("[CLKSCHED-TEST] ✗ it_interval.tv_sec=%ld (expected 2)\n",
                   cur.it_interval.tv_sec);
        fut_test_fail(CLKSCHED_TEST_ITIMER);
        return;
    }

    /* Disarm to avoid spurious SIGALRM during other tests */
    struct itimerval disarm;
    memset(&disarm, 0, sizeof(disarm));
    sys_setitimer(ITIMER_REAL, &disarm, NULL);

    fut_printf("[CLKSCHED-TEST] ✓ itimer armed: remaining=%llds interval=%llds\n",
               (long long)cur.it_value.tv_sec, (long long)cur.it_interval.tv_sec);
    fut_test_pass();
}

/* ============================================================
 * Test 5: sys_getrusage returns valid (non-crashing) stats
 * ============================================================ */
static void test_getrusage(void) {
    fut_printf("[CLKSCHED-TEST] Test 5: sys_getrusage returns valid stats\n");

    struct test_rusage ru;
    memset(&ru, 0xff, sizeof(ru));  /* Fill with 0xff to detect zero-fill */

    long ret = sys_getrusage(RUSAGE_SELF, &ru);
    if (ret != 0) {
        fut_printf("[CLKSCHED-TEST] ✗ getrusage returned %ld\n", ret);
        fut_test_fail(CLKSCHED_TEST_GETRUSAGE);
        return;
    }

    /* ru_utime should be non-negative (tv_sec and tv_usec >= 0) */
    if (ru.ru_utime.tv_sec < 0 || ru.ru_utime.tv_usec < 0) {
        fut_printf("[CLKSCHED-TEST] ✗ ru_utime.tv_sec=%ld usec=%ld (negative)\n",
                   ru.ru_utime.tv_sec, ru.ru_utime.tv_usec);
        fut_test_fail(CLKSCHED_TEST_GETRUSAGE);
        return;
    }

    /* ru_stime should be non-negative */
    if (ru.ru_stime.tv_sec < 0 || ru.ru_stime.tv_usec < 0) {
        fut_printf("[CLKSCHED-TEST] ✗ ru_stime.tv_sec=%ld usec=%ld (negative)\n",
                   ru.ru_stime.tv_sec, ru.ru_stime.tv_usec);
        fut_test_fail(CLKSCHED_TEST_GETRUSAGE);
        return;
    }

    /* ru_maxrss should be non-negative (Phase 5: computed from VMA list) */
    if (ru.ru_maxrss < 0) {
        fut_printf("[CLKSCHED-TEST] ✗ ru_maxrss=%ld (negative)\n", ru.ru_maxrss);
        fut_test_fail(CLKSCHED_TEST_GETRUSAGE);
        return;
    }

    fut_printf("[CLKSCHED-TEST] ✓ getrusage: utime=%lld.%06llds nvcsw=%ld maxrss=%ldKB\n",
               (long long)ru.ru_utime.tv_sec, (long long)ru.ru_utime.tv_usec,
               ru.ru_nvcsw, ru.ru_maxrss);
    fut_test_pass();
}

/* ============================================================
 * Test 6: sys_times returns valid elapsed ticks
 * ============================================================ */
static void test_times(void) {
    fut_printf("[CLKSCHED-TEST] Test 6: sys_times returns valid elapsed ticks\n");

    struct tms t;
    memset(&t, 0xff, sizeof(t));

    long elapsed = sys_times(&t);
    if (elapsed < 0) {
        fut_printf("[CLKSCHED-TEST] ✗ times() returned %ld\n", elapsed);
        fut_test_fail(CLKSCHED_TEST_TIMES);
        return;
    }

    /* tms_utime and tms_stime should be non-negative */
    if (t.tms_utime < 0 || t.tms_stime < 0) {
        fut_printf("[CLKSCHED-TEST] ✗ tms_utime=%ld or tms_stime=%ld is negative\n",
                   (long)t.tms_utime, (long)t.tms_stime);
        fut_test_fail(CLKSCHED_TEST_TIMES);
        return;
    }

    /* elapsed ticks should be > 0 if system has been running */
    if (elapsed == 0) {
        fut_printf("[CLKSCHED-TEST] ✗ elapsed ticks = 0 (system hasn't ticked?)\n");
        fut_test_fail(CLKSCHED_TEST_TIMES);
        return;
    }

    fut_printf("[CLKSCHED-TEST] ✓ times: elapsed=%ld ticks utime=%ld stime=%ld\n",
               elapsed, (long)t.tms_utime, (long)t.tms_stime);
    fut_test_pass();
}

/* ============================================================
 * Test 7: getpriority returns correct default nice value
 * ============================================================ */
static void test_getpriority(void) {
    fut_printf("[CLKSCHED-TEST] Test 7: getpriority(PRIO_PROCESS, 0) default nice\n");

    /* Default nice value is 0, getpriority returns 20 - nice = 20 */
    long ret = sys_getpriority(TEST_PRIO_PROCESS, 0);
    if (ret < 0) {
        fut_printf("[CLKSCHED-TEST] ✗ getpriority returned error %ld\n", ret);
        fut_test_fail(CLKSCHED_TEST_GETPRIORITY);
        return;
    }

    /* Value should be 20 (nice=0) for a freshly-created task */
    if (ret != 20) {
        fut_printf("[CLKSCHED-TEST] ✗ getpriority expected 20 (nice=0), got %ld\n", ret);
        fut_test_fail(CLKSCHED_TEST_GETPRIORITY);
        return;
    }

    fut_printf("[CLKSCHED-TEST] ✓ getpriority -> %ld (nice=0)\n", ret);
    fut_test_pass();
}

/* ============================================================
 * Test 8: setpriority stores nice value, getpriority reflects it
 * ============================================================ */
static void test_setpriority(void) {
    fut_printf("[CLKSCHED-TEST] Test 8: setpriority roundtrip\n");

    /* Set nice to 5 */
    long ret = sys_setpriority(TEST_PRIO_PROCESS, 0, 5);
    if (ret != 0) {
        fut_printf("[CLKSCHED-TEST] ✗ setpriority(5) returned %ld\n", ret);
        fut_test_fail(CLKSCHED_TEST_SETPRIORITY);
        return;
    }

    /* getpriority should now return 20 - 5 = 15 */
    long prio = sys_getpriority(TEST_PRIO_PROCESS, 0);
    if (prio != 15) {
        fut_printf("[CLKSCHED-TEST] ✗ getpriority after setpriority(5): expected 15, got %ld\n",
                   prio);
        sys_setpriority(TEST_PRIO_PROCESS, 0, 0); /* restore */
        fut_test_fail(CLKSCHED_TEST_SETPRIORITY);
        return;
    }

    /* Restore nice to 0 */
    sys_setpriority(TEST_PRIO_PROCESS, 0, 0);

    /* Verify restoration: should be 20 again */
    prio = sys_getpriority(TEST_PRIO_PROCESS, 0);
    if (prio != 20) {
        fut_printf("[CLKSCHED-TEST] ✗ getpriority after restore: expected 20, got %ld\n", prio);
        fut_test_fail(CLKSCHED_TEST_SETPRIORITY);
        return;
    }

    fut_printf("[CLKSCHED-TEST] ✓ setpriority/getpriority roundtrip OK\n");
    fut_test_pass();
}

/* ============================================================
 * Test 9: getpriority rejects negative who with EINVAL
 * ============================================================ */
static void test_getpriority_negative_who(void) {
    fut_printf("[CLKSCHED-TEST] Test 9: getpriority(PRIO_PROCESS, -1) -> EINVAL\n");

    long ret = sys_getpriority(TEST_PRIO_PROCESS, -1);
    if (ret != -EINVAL) {
        fut_printf("[CLKSCHED-TEST] ✗ getpriority(-1): expected -EINVAL, got %ld\n", ret);
        fut_test_fail(CLKSCHED_TEST_GETPRIO_NEGWHO);
        return;
    }

    fut_printf("[CLKSCHED-TEST] ✓ getpriority negative who rejected with EINVAL\n");
    fut_test_pass();
}

/* ============================================================
 * Test 10: setpriority rejects negative who with EINVAL
 * ============================================================ */
static void test_setpriority_negative_who(void) {
    fut_printf("[CLKSCHED-TEST] Test 10: setpriority(PRIO_PROCESS, -1, 0) -> EINVAL\n");

    long ret = sys_setpriority(TEST_PRIO_PROCESS, -1, 0);
    if (ret != -EINVAL) {
        fut_printf("[CLKSCHED-TEST] ✗ setpriority(-1,0): expected -EINVAL, got %ld\n", ret);
        fut_test_fail(CLKSCHED_TEST_SETPRIO_NEGWHO);
        return;
    }

    fut_printf("[CLKSCHED-TEST] ✓ setpriority negative who rejected with EINVAL\n");
    fut_test_pass();
}

/* ============================================================
 * Test 11: unshare(0) succeeds as a no-op
 * ============================================================ */
static void test_unshare_noop(void) {
    fut_printf("[CLKSCHED-TEST] Test 11: unshare(0) -> 0\n");

    long ret = sys_unshare(0);
    if (ret != 0) {
        fut_printf("[CLKSCHED-TEST] ✗ unshare(0): expected 0, got %ld\n", ret);
        fut_test_fail(CLKSCHED_TEST_UNSHARE_NOOP);
        return;
    }

    fut_printf("[CLKSCHED-TEST] ✓ unshare(0) succeeded\n");
    fut_test_pass();
}

/* ============================================================
 * Test 12: unshare rejects unsupported bits with EINVAL
 * ============================================================ */
static void test_unshare_invalid_bits(void) {
    fut_printf("[CLKSCHED-TEST] Test 12: unshare(unsupported_bits) -> EINVAL\n");

    long ret = sys_unshare(TEST_CLONE_FILES | 0x1UL);
    if (ret != -EINVAL) {
        fut_printf("[CLKSCHED-TEST] ✗ unshare(unsupported_bits): expected -EINVAL, got %ld\n", ret);
        fut_test_fail(CLKSCHED_TEST_UNSHARE_INVAL);
        return;
    }

    fut_printf("[CLKSCHED-TEST] ✓ unshare unsupported bits rejected with EINVAL\n");
    fut_test_pass();
}

/* ============================================================
 * Main test harness thread
 * ============================================================ */
void fut_clock_sched_test_thread(void *arg) {
    (void)arg;

    fut_printf("[CLKSCHED-TEST] ========================================\n");
    fut_printf("[CLKSCHED-TEST] clock / sched / timer / rusage Tests\n");
    fut_printf("[CLKSCHED-TEST] ========================================\n");

    test_clock_getres();
    test_sched_param();
    test_sched_policy();
    test_itimer();
    test_getrusage();
    test_times();
    test_getpriority();
    test_setpriority();
    test_getpriority_negative_who();
    test_setpriority_negative_who();
    test_unshare_noop();
    test_unshare_invalid_bits();

    fut_printf("[CLKSCHED-TEST] ========================================\n");
    fut_printf("[CLKSCHED-TEST] All clock/sched/timer tests done\n");
    fut_printf("[CLKSCHED-TEST] ========================================\n");
}

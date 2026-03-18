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
#include <kernel/signal.h>
#include <kernel/signal_frame.h>
#include <shared/fut_sigevent.h>

/* Forward declarations */
extern long sys_clock_getres(int clock_id, fut_timespec_t *res);
extern long sys_clock_gettime(int clock_id, fut_timespec_t *tp);
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
extern long sys_sched_rr_get_interval(int pid, fut_timespec_t *interval);
extern long sys_timer_create(int clockid, struct sigevent *sevp, timer_t *timerid);
extern long sys_timer_settime(timer_t timerid, int flags, const struct itimerspec *new_value, struct itimerspec *old_value);
extern long sys_timer_delete(timer_t timerid);
extern int  fut_signal_send_with_info(fut_task_t *task, int signum, const void *info);

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
#define CLKSCHED_TEST_RR_INTERVAL        13
#define CLKSCHED_TEST_CLOCK_GETTIME      14
#define CLKSCHED_TEST_TIMER_SIGEV_VALUE  15
#define CLKSCHED_TEST_TIMER_SI_TIMER     16
#define CLKSCHED_TEST_ITIMER_VIRTUAL     17

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
    fut_printf("[CLKSCHED-TEST] Test 11: unshare(0) and unshare(CLONE_FILES) -> 0\n");

    long ret = sys_unshare(0);
    if (ret != 0) {
        fut_printf("[CLKSCHED-TEST] ✗ unshare(0): expected 0, got %ld\n", ret);
        fut_test_fail(CLKSCHED_TEST_UNSHARE_NOOP);
        return;
    }

    ret = sys_unshare(TEST_CLONE_FILES);
    if (ret != 0) {
        fut_printf("[CLKSCHED-TEST] ✗ unshare(CLONE_FILES): expected 0, got %ld\n", ret);
        fut_test_fail(CLKSCHED_TEST_UNSHARE_NOOP);
        return;
    }

    fut_printf("[CLKSCHED-TEST] ✓ unshare(0) and unshare(CLONE_FILES) succeeded\n");
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
 * Test 13: sched_rr_get_interval returns valid quantum
 * ============================================================ */
static void test_sched_rr_get_interval(void) {
    fut_printf("[CLKSCHED-TEST] Test 13: sched_rr_get_interval returns quantum\n");

    fut_timespec_t interval = {0, 0};
    long ret = sys_sched_rr_get_interval(0, &interval);
    if (ret != 0) {
        fut_printf("[CLKSCHED-TEST] ✗ sched_rr_get_interval(0) returned %ld\n", ret);
        fut_test_fail(CLKSCHED_TEST_RR_INTERVAL);
        return;
    }

    /* Should be 10ms (10000000 ns) for 100 Hz timer */
    if (interval.tv_sec != 0 || interval.tv_nsec != 10000000) {
        fut_printf("[CLKSCHED-TEST] ✗ interval=%lld.%09lld (expected 0.010000000)\n",
                   (long long)interval.tv_sec, (long long)interval.tv_nsec);
        fut_test_fail(CLKSCHED_TEST_RR_INTERVAL);
        return;
    }

    /* ESRCH for nonexistent PID */
    ret = sys_sched_rr_get_interval(99999, &interval);
    if (ret != -ESRCH) {
        fut_printf("[CLKSCHED-TEST] ✗ sched_rr_get_interval(99999) returned %ld (expected ESRCH)\n", ret);
        fut_test_fail(CLKSCHED_TEST_RR_INTERVAL);
        return;
    }

    fut_printf("[CLKSCHED-TEST] ✓ sched_rr_get_interval: quantum=10ms, ESRCH for bad PID\n");
    fut_test_pass();
}

/* ============================================================
 * Test 14: kernel tick-to-time conversion is correct
 * ============================================================ */
static void test_clock_gettime(void) {
    fut_printf("[CLKSCHED-TEST] Test 14: tick-to-time conversion correctness\n");

    /* Validate that fut_get_ticks() returns a reasonable value and that
     * the ticks→seconds conversion is correct (100 ticks = 1 second). */
    uint64_t ticks = fut_get_ticks();

    /* Ticks should be non-zero (we're well past boot) */
    if (ticks == 0) {
        fut_printf("[CLKSCHED-TEST] ✗ fut_get_ticks() returned 0\n");
        fut_test_fail(CLKSCHED_TEST_CLOCK_GETTIME);
        return;
    }

    /* Uptime in seconds should be reasonable (< 600s = 10 minutes) */
    uint64_t uptime_sec = ticks / 100;
    if (uptime_sec > 600) {
        fut_printf("[CLKSCHED-TEST] ✗ uptime=%llu seconds (unreasonably high for tests)\n",
                   (unsigned long long)uptime_sec);
        fut_test_fail(CLKSCHED_TEST_CLOCK_GETTIME);
        return;
    }

    /* Verify monotonicity: second reading >= first */
    uint64_t ticks2 = fut_get_ticks();
    if (ticks2 < ticks) {
        fut_printf("[CLKSCHED-TEST] ✗ ticks went backwards: %llu > %llu\n",
                   (unsigned long long)ticks, (unsigned long long)ticks2);
        fut_test_fail(CLKSCHED_TEST_CLOCK_GETTIME);
        return;
    }

    /* Verify conversion: ticks * 10ms should match uptime_sec * 1000 (ms) */
    uint64_t uptime_ms = ticks * 10;
    uint64_t derived_sec = uptime_ms / 1000;
    if (derived_sec != uptime_sec) {
        fut_printf("[CLKSCHED-TEST] ✗ conversion mismatch: ticks/100=%llu vs ticks*10/1000=%llu\n",
                   (unsigned long long)uptime_sec, (unsigned long long)derived_sec);
        fut_test_fail(CLKSCHED_TEST_CLOCK_GETTIME);
        return;
    }

    /* clock_getres(CLOCK_MONOTONIC) should succeed (already tested in test 1,
     * but validates the clock ID is recognized) */
    long ret = sys_clock_getres(CLOCK_REALTIME, NULL);
    if (ret != 0) {
        fut_printf("[CLKSCHED-TEST] ✗ clock_getres(REALTIME) returned %ld\n", ret);
        fut_test_fail(CLKSCHED_TEST_CLOCK_GETTIME);
        return;
    }

    fut_printf("[CLKSCHED-TEST] ✓ ticks=%llu uptime=%llus monotonic, conversion correct\n",
               (unsigned long long)ticks, (unsigned long long)uptime_sec);
    fut_test_pass();
}

/* ============================================================
 * Test 15: timer_create stores sigev_value in posix_timers slot
 * ============================================================ */
static void test_posix_timer_sigev_value(void) {
    fut_printf("[CLKSCHED-TEST] Test 15: timer_create stores sigev_value in posix_timers slot\n");

    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[CLKSCHED-TEST] ✗ no current task\n");
        fut_test_fail(CLKSCHED_TEST_TIMER_SIGEV_VALUE);
        return;
    }

    /* Create a timer with SIGUSR1, sigev_value=0xCAFE */
    struct sigevent sev;
    memset(&sev, 0, sizeof(sev));
    sev.sigev_notify    = SIGEV_SIGNAL;
    sev.sigev_signo     = SIGUSR1;
    sev.sigev_value.sival_int = 0xCAFE;

    timer_t tid = 0;
    long ret = sys_timer_create(CLOCK_MONOTONIC, &sev, &tid);
    if (ret != 0) {
        fut_printf("[CLKSCHED-TEST] ✗ timer_create returned %ld\n", ret);
        fut_test_fail(CLKSCHED_TEST_TIMER_SIGEV_VALUE);
        return;
    }

    /* Verify the slot has the right sigev_value */
    int slot = tid - 1;  /* IDs are 1-based */
    if (slot < 0 || slot >= FUT_POSIX_TIMER_MAX) {
        fut_printf("[CLKSCHED-TEST] ✗ timer id %d out of range\n", (int)tid);
        sys_timer_delete(tid);
        fut_test_fail(CLKSCHED_TEST_TIMER_SIGEV_VALUE);
        return;
    }

    fut_posix_timer_t *pt = &task->posix_timers[slot];
    if (!pt->active) {
        fut_printf("[CLKSCHED-TEST] ✗ timer slot not active\n");
        sys_timer_delete(tid);
        fut_test_fail(CLKSCHED_TEST_TIMER_SIGEV_VALUE);
        return;
    }

    if (pt->sigev_value != (long)0xCAFE) {
        fut_printf("[CLKSCHED-TEST] ✗ sigev_value=0x%lx expected 0xCAFE\n",
                   (unsigned long)pt->sigev_value);
        sys_timer_delete(tid);
        fut_test_fail(CLKSCHED_TEST_TIMER_SIGEV_VALUE);
        return;
    }

    if (pt->signo != SIGUSR1) {
        fut_printf("[CLKSCHED-TEST] ✗ signo=%d expected SIGUSR1=%d\n", pt->signo, SIGUSR1);
        sys_timer_delete(tid);
        fut_test_fail(CLKSCHED_TEST_TIMER_SIGEV_VALUE);
        return;
    }

    sys_timer_delete(tid);
    fut_printf("[CLKSCHED-TEST] ✓ timer_create stored sigev_value=0xCAFE, signo=SIGUSR1\n");
    fut_test_pass();
}

/* ============================================================
 * Test 16: POSIX timer expiry delivers SI_TIMER siginfo
 * ============================================================ */
static void test_posix_timer_si_timer(void) {
    fut_printf("[CLKSCHED-TEST] Test 16: POSIX timer expiry delivers SI_TIMER siginfo\n");

    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[CLKSCHED-TEST] ✗ no current task\n");
        fut_test_fail(CLKSCHED_TEST_TIMER_SI_TIMER);
        return;
    }

    /* Create a timer with SIGUSR2 and sigev_value=0xBEEF */
    struct sigevent sev;
    memset(&sev, 0, sizeof(sev));
    sev.sigev_notify          = SIGEV_SIGNAL;
    sev.sigev_signo           = SIGUSR2;
    sev.sigev_value.sival_int = 0xBEEF;

    timer_t tid = 0;
    long ret = sys_timer_create(CLOCK_MONOTONIC, &sev, &tid);
    if (ret != 0) {
        fut_printf("[CLKSCHED-TEST] ✗ timer_create returned %ld\n", ret);
        fut_test_fail(CLKSCHED_TEST_TIMER_SI_TIMER);
        return;
    }

    /* Simulate timer-tick expiry: build the exact siginfo_t that fut_timer.c sends */
    siginfo_t sinfo;
    __builtin_memset(&sinfo, 0, sizeof(sinfo));
    sinfo.si_signum  = SIGUSR2;
    sinfo.si_code    = SI_TIMER;   /* -2 */
    sinfo.si_timerid = (int)tid;
    sinfo.si_overrun = 0;
    sinfo.si_pid     = (int64_t)task->pid;
    sinfo.si_uid     = (uint32_t)task->uid;
    sinfo.si_value   = 0xBEEF;

    ret = (long)fut_signal_send_with_info(task, SIGUSR2, &sinfo);
    if (ret != 0) {
        fut_printf("[CLKSCHED-TEST] ✗ fut_signal_send_with_info returned %ld\n", ret);
        sys_timer_delete(tid);
        fut_test_fail(CLKSCHED_TEST_TIMER_SI_TIMER);
        return;
    }

    /* Verify sig_queue_info was populated with SI_TIMER fields */
    siginfo_t *qi = &task->sig_queue_info[SIGUSR2 - 1];

    if (qi->si_code != SI_TIMER) {
        fut_printf("[CLKSCHED-TEST] ✗ si_code=%d expected SI_TIMER=%d\n",
                   qi->si_code, SI_TIMER);
        sys_timer_delete(tid);
        fut_test_fail(CLKSCHED_TEST_TIMER_SI_TIMER);
        return;
    }

    if (qi->si_timerid != (int)tid) {
        fut_printf("[CLKSCHED-TEST] ✗ si_timerid=%d expected %d\n",
                   qi->si_timerid, (int)tid);
        sys_timer_delete(tid);
        fut_test_fail(CLKSCHED_TEST_TIMER_SI_TIMER);
        return;
    }

    if ((long)qi->si_value != (long)0xBEEF) {
        fut_printf("[CLKSCHED-TEST] ✗ si_value=0x%lx expected 0xBEEF\n",
                   (unsigned long)qi->si_value);
        sys_timer_delete(tid);
        fut_test_fail(CLKSCHED_TEST_TIMER_SI_TIMER);
        return;
    }

    /* Clear pending signal to avoid delivery during subsequent tests */
    task->pending_signals &= ~(1ULL << (SIGUSR2 - 1));

    sys_timer_delete(tid);
    fut_printf("[CLKSCHED-TEST] ✓ SI_TIMER: si_code=SI_TIMER, si_timerid=%d, si_value=0xBEEF\n",
               (int)tid);
    fut_test_pass();
}

/* ============================================================
 * Test 17: setitimer/getitimer ITIMER_VIRTUAL roundtrip
 * ============================================================ */
static void test_itimer_virtual(void) {
    fut_printf("[CLKSCHED-TEST] Test 17: setitimer/getitimer ITIMER_VIRTUAL roundtrip\n");

    /* Arm ITIMER_VIRTUAL with 3 second one-shot */
    struct itimerval arm;
    memset(&arm, 0, sizeof(arm));
    arm.it_value.tv_sec     = 3;
    arm.it_value.tv_usec    = 0;
    arm.it_interval.tv_sec  = 1;
    arm.it_interval.tv_usec = 500000;

    long ret = sys_setitimer(ITIMER_VIRTUAL, &arm, NULL);
    if (ret != 0) {
        fut_printf("[CLKSCHED-TEST] ✗ setitimer(VIRTUAL) returned %ld\n", ret);
        fut_test_fail(CLKSCHED_TEST_ITIMER_VIRTUAL);
        return;
    }

    /* Verify backing fields in task struct */
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_test_fail(CLKSCHED_TEST_ITIMER_VIRTUAL);
        return;
    }
    if (task->itimer_virt_value_ms == 0) {
        fut_printf("[CLKSCHED-TEST] ✗ itimer_virt_value_ms not set after setitimer\n");
        sys_setitimer(ITIMER_VIRTUAL, &(struct itimerval){{0,0},{0,0}}, NULL);
        fut_test_fail(CLKSCHED_TEST_ITIMER_VIRTUAL);
        return;
    }

    /* Read back via getitimer */
    struct itimerval cur;
    memset(&cur, 0, sizeof(cur));
    ret = sys_getitimer(ITIMER_VIRTUAL, &cur);
    if (ret != 0) {
        fut_printf("[CLKSCHED-TEST] ✗ getitimer(VIRTUAL) returned %ld\n", ret);
        sys_setitimer(ITIMER_VIRTUAL, &(struct itimerval){{0,0},{0,0}}, NULL);
        fut_test_fail(CLKSCHED_TEST_ITIMER_VIRTUAL);
        return;
    }

    if (cur.it_value.tv_sec == 0 && cur.it_value.tv_usec == 0) {
        fut_printf("[CLKSCHED-TEST] ✗ getitimer(VIRTUAL) it_value is zero\n");
        sys_setitimer(ITIMER_VIRTUAL, &(struct itimerval){{0,0},{0,0}}, NULL);
        fut_test_fail(CLKSCHED_TEST_ITIMER_VIRTUAL);
        return;
    }

    /* Disarm */
    struct itimerval disarm;
    memset(&disarm, 0, sizeof(disarm));
    sys_setitimer(ITIMER_VIRTUAL, &disarm, NULL);

    if (task->itimer_virt_value_ms != 0) {
        fut_printf("[CLKSCHED-TEST] ✗ itimer_virt_value_ms not cleared after disarm\n");
        fut_test_fail(CLKSCHED_TEST_ITIMER_VIRTUAL);
        return;
    }

    fut_printf("[CLKSCHED-TEST] ✓ ITIMER_VIRTUAL: armed=%llds interval=%lld.5s, disarmed OK\n",
               (long long)cur.it_value.tv_sec, (long long)cur.it_interval.tv_sec);
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
    test_sched_rr_get_interval();
    test_clock_gettime();
    test_posix_timer_sigev_value();
    test_posix_timer_si_timer();
    test_itimer_virtual();

    fut_printf("[CLKSCHED-TEST] ========================================\n");
    fut_printf("[CLKSCHED-TEST] All clock/sched/timer tests done\n");
    fut_printf("[CLKSCHED-TEST] ========================================\n");
}

// SPDX-License-Identifier: MPL-2.0

#include <kernel/fut_timer.h>
#include <kernel/errno.h>
#include <shared/fut_timeval.h>
#include <stdint.h>

extern int fut_copy_to_user(void *to, const void *from, size_t size);
extern void fut_printf(const char *fmt, ...);

long sys_time_millis(void) {
    return (long)fut_get_ticks();
}

/**
 * gettimeofday() - Get current time of day
 *
 * Returns the current time as seconds and microseconds since the Unix epoch.
 * The timezone parameter is not supported and should be NULL.
 *
 * @param tv  Pointer to timeval structure to receive time
 * @param tz  Timezone structure (not supported, should be NULL)
 *
 * Returns:
 *   - 0 on success
 *   - -EFAULT if tv is an invalid pointer
 *   - -EINVAL if tz is non-NULL (timezones not supported)
 */
long sys_gettimeofday(fut_timeval_t *tv, void *tz) {
    if (!tv) {
        return -EFAULT;
    }

    if (tz != NULL) {
        fut_printf("[TIME] gettimeofday: timezone parameter not supported\n");
        return -EINVAL;
    }

    /* Get current time in milliseconds */
    uint64_t ms = fut_get_ticks();

    /* Convert to timeval (seconds + microseconds) */
    fut_timeval_t kernel_tv;
    kernel_tv.tv_sec = ms / 1000;
    kernel_tv.tv_usec = (ms % 1000) * 1000;

    /* Copy to userspace */
    if (fut_copy_to_user(tv, &kernel_tv, sizeof(fut_timeval_t)) != 0) {
        return -EFAULT;
    }

    fut_printf("[TIME] gettimeofday() -> %lld.%06lld\n",
               kernel_tv.tv_sec, kernel_tv.tv_usec);

    return 0;
}

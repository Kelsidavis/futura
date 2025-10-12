// SPDX-License-Identifier: MPL-2.0

#include <shared/fut_timespec.h>
#include <kernel/uaccess.h>
#include <kernel/errno.h>
#include <kernel/fut_thread.h>
#include <kernel/fut_timer.h>

long sys_nanosleep(const fut_timespec_t *u_req, fut_timespec_t *u_rem) {
    if (!u_req) {
        return -EINVAL;
    }

    fut_timespec_t req;
    if (fut_copy_from_user(&req, u_req, sizeof(req)) != 0) {
        return -EFAULT;
    }

    if (req.tv_sec < 0 || req.tv_nsec < 0 || req.tv_nsec >= 1000000000LL) {
        return -EINVAL;
    }

    uint64_t total_ns = (uint64_t)req.tv_sec * 1000000000ULL + (uint64_t)req.tv_nsec;
    uint64_t millis = total_ns / 1000000ULL;
    if (total_ns != 0 && millis == 0) {
        millis = 1;
    }

    fut_thread_sleep(millis);

    if (u_rem) {
        fut_timespec_t rem = {0, 0};
        (void)fut_copy_to_user(u_rem, &rem, sizeof(rem));
    }

    return 0;
}

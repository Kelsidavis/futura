#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <limits.h>

#include <shared/fut_timespec.h>
#include <user/sys.h>
#include <sys/timerfd.h>
#include <user/time.h>
#include "timerfd_internal.h"

#ifndef EPOLLIN
#define EPOLLIN 0x001u
#endif

struct fut_timerfd {
    bool in_use;
    int handle;
    bool armed;
    uint64_t next_expiry_ms;
    uint64_t interval_ms;
    uint64_t pending_expirations;
    int flags;
};

#define MAX_TIMERFDS 16

static struct fut_timerfd timerfds[MAX_TIMERFDS];
static int next_timerfd_handle = 64; /* avoid stdio descriptors */

static uint64_t now_ms(void) {
    return (uint64_t)sys_time_millis_call();
}

static uint64_t timespec_to_ms(const struct timespec *ts) {
    if (!ts) {
        return 0;
    }
    int64_t sec = ts->tv_sec;
    int64_t nsec = ts->tv_nsec;
    if (sec < 0) {
        sec = 0;
    }
    if (nsec < 0) {
        nsec = 0;
    }
    uint64_t total_ms = (uint64_t)sec * 1000ULL;
    total_ms += (uint64_t)nsec / 1000000ULL;
    return total_ms;
}

static struct timespec ms_to_timespec(uint64_t ms) {
    struct timespec ts;
    ts.tv_sec = (long)(ms / 1000ULL);
    ts.tv_nsec = (long)((ms % 1000ULL) * 1000000ULL);
    return ts;
}

static struct fut_timerfd *lookup_timerfd(int fd) {
    for (int i = 0; i < MAX_TIMERFDS; ++i) {
        if (timerfds[i].in_use && timerfds[i].handle == fd) {
            return &timerfds[i];
        }
    }
    return NULL;
}

static void accrue_pending(struct fut_timerfd *t, uint64_t now) {
    if (!t || !t->armed) {
        return;
    }

    if (t->next_expiry_ms > now) {
        return;
    }

    if (t->interval_ms == 0) {
        t->pending_expirations += 1;
        t->armed = false;
        t->next_expiry_ms = 0;
        return;
    }

    uint64_t delta = now - t->next_expiry_ms;
    uint64_t intervals = delta / t->interval_ms;
    t->pending_expirations += 1 + intervals;
    t->next_expiry_ms = t->next_expiry_ms + (intervals + 1ULL) * t->interval_ms;
}

int timerfd_create(int clockid, int flags) {
    (void)flags;
    if (clockid != CLOCK_MONOTONIC) {
        return -1;
    }

    for (int i = 0; i < MAX_TIMERFDS; ++i) {
        if (!timerfds[i].in_use) {
            timerfds[i].in_use = true;
            timerfds[i].handle = next_timerfd_handle++;
            timerfds[i].armed = false;
            timerfds[i].next_expiry_ms = 0;
            timerfds[i].interval_ms = 0;
            timerfds[i].pending_expirations = 0;
            timerfds[i].flags = flags;
            return timerfds[i].handle;
        }
    }
    return -1;
}

int timerfd_settime(int fd, int flags,
                    const struct itimerspec *new_value,
                    struct itimerspec *old_value) {
    struct fut_timerfd *t = lookup_timerfd(fd);
    if (!t || !new_value) {
        return -1;
    }

    uint64_t now = now_ms();

    if (old_value) {
        if (t->armed) {
            uint64_t remaining = (t->next_expiry_ms > now) ? (t->next_expiry_ms - now) : 0;
            old_value->it_value = ms_to_timespec(remaining);
        } else {
            old_value->it_value = ms_to_timespec(0);
        }
        old_value->it_interval = ms_to_timespec(t->interval_ms);
    }

    uint64_t new_interval = timespec_to_ms(&new_value->it_interval);
    uint64_t new_initial = timespec_to_ms(&new_value->it_value);

    if (new_initial == 0) {
        t->armed = false;
        t->next_expiry_ms = 0;
        t->interval_ms = new_interval;
        t->pending_expirations = 0;
        return 0;
    }

    if (flags & TFD_TIMER_ABSTIME) {
        t->next_expiry_ms = new_initial;
    } else {
        t->next_expiry_ms = now + new_initial;
    }
    t->interval_ms = new_interval;
    t->armed = true;
    t->pending_expirations = 0;
    return 0;
}

int timerfd_gettime(int fd, struct itimerspec *curr_value) {
    struct fut_timerfd *t = lookup_timerfd(fd);
    if (!t || !curr_value) {
        return -1;
    }

    uint64_t now = now_ms();
    accrue_pending(t, now);

    if (t->armed && t->next_expiry_ms > now) {
        curr_value->it_value = ms_to_timespec(t->next_expiry_ms - now);
    } else {
        curr_value->it_value = ms_to_timespec(0);
    }
    curr_value->it_interval = ms_to_timespec(t->interval_ms);
    return 0;
}

int __fut_timerfd_close(int fd) {
    struct fut_timerfd *t = lookup_timerfd(fd);
    if (!t) {
        return -1;
    }
    t->in_use = false;
    t->armed = false;
    t->pending_expirations = 0;
    t->next_expiry_ms = 0;
    t->interval_ms = 0;
    return 0;
}

int __fut_timerfd_is_timer(int fd) {
    return lookup_timerfd(fd) ? 1 : 0;
}

int __fut_timerfd_poll(int fd, uint32_t *events_out) {
    struct fut_timerfd *t = lookup_timerfd(fd);
    if (!t) {
        return 0;
    }

    accrue_pending(t, now_ms());
    if (t->pending_expirations == 0) {
        return 0;
    }

    if (events_out) {
        *events_out = EPOLLIN;
    }
    return 1;
}

int __fut_timerfd_next_timeout_ms(void) {
    uint64_t now = now_ms();
    bool have_timer = false;
    uint64_t min_ms = 0;

    for (int i = 0; i < MAX_TIMERFDS; ++i) {
        struct fut_timerfd *t = &timerfds[i];
        if (!t->in_use || !t->armed) {
            continue;
        }
        accrue_pending(t, now);
        if (t->pending_expirations > 0) {
            return 0;
        }
        if (t->next_expiry_ms <= now) {
            return 0;
        }
        uint64_t diff = t->next_expiry_ms - now;
        if (!have_timer || diff < min_ms) {
            min_ms = diff;
            have_timer = true;
        }
    }

    if (!have_timer) {
        return -1;
    }
    if (min_ms > (uint64_t)INT32_MAX) {
        return INT32_MAX;
    }
    return (int)min_ms;
}

uint64_t __fut_timerfd_pending(int fd) {
    struct fut_timerfd *t = lookup_timerfd(fd);
    if (!t) {
        return 0;
    }
    accrue_pending(t, now_ms());
    return t->pending_expirations;
}

int __fut_timerfd_disarm(int fd) {
    struct fut_timerfd *t = lookup_timerfd(fd);
    if (!t) {
        return -1;
    }
    t->armed = false;
    t->next_expiry_ms = 0;
    t->interval_ms = 0;
    t->pending_expirations = 0;
    return 0;
}

ssize_t __fut_timerfd_read(int fd, void *buf, size_t count) {
    struct fut_timerfd *t = lookup_timerfd(fd);
    if (!t || !buf || count < sizeof(uint64_t)) {
        return -1;
    }

    accrue_pending(t, now_ms());
    if (t->pending_expirations == 0) {
        return -1;
    }

    uint64_t expirations = t->pending_expirations;
    uint8_t *dst = (uint8_t *)buf;
    for (size_t i = 0; i < sizeof(uint64_t); ++i) {
        dst[i] = (uint8_t)((expirations >> (i * 8)) & 0xFF);
    }
    t->pending_expirations = 0;
    return (ssize_t)sizeof(uint64_t);
}

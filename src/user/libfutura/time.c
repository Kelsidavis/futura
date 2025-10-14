#include <stdint.h>
#include <stddef.h>

#include <user/sys.h>
#include <user/time.h>

int clock_gettime(int clock_id, struct timespec *tp) {
    (void)clock_id;
    if (!tp) {
        return -1;
    }

    long ms = (long)sys_time_millis_call();
    tp->tv_sec = ms / 1000;
    tp->tv_nsec = (ms % 1000) * 1000000L;
    return 0;
}

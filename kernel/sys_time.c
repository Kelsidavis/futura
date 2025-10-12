// SPDX-License-Identifier: MPL-2.0

#include <kernel/fut_timer.h>

long sys_time_millis(void) {
    return (long)fut_get_ticks();
}

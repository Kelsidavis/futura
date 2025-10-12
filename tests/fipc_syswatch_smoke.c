// SPDX-License-Identifier: MPL-2.0
// Emit a few system metrics frames for syswatch smoke coverage.

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>

#include <kernel/fut_fipc.h>
#include <kernel/fut_fipc_sys.h>

#include "../src/user/sys/fipc_sys.h"

int main(void) {
    fut_fipc_init();

    struct fut_fipc_channel *sys_channel = fut_fipc_channel_lookup(FIPC_SYS_CHANNEL_ID);
    if (!sys_channel) {
        if (fut_fipc_channel_create(NULL,
                                    NULL,
                                    4096,
                                    FIPC_CHANNEL_NONBLOCKING,
                                    &sys_channel) != 0 || !sys_channel) {
            return 1;
        }
        sys_channel->id = FIPC_SYS_CHANNEL_ID;
        sys_channel->type = FIPC_CHANNEL_SYSTEM;
    }

    (void)fipc_sys_publish_kernel_metrics();
    (void)fipc_sys_fway_surface_create(1, 100, 10, 12);
    (void)fipc_sys_vfs_write("/tmp/syswatch", 512, 0, 12, 22);

    printf("[SYSWATCH-SMOKE] emitted frames\n");
    return 0;
}

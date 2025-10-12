/* fipc_sys_pub_kernelshim.c - compatibility wrapper for kernel metrics publish
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * Retained so existing host tests can request kernel metrics via the
 * historical fipc_sys_publish_kernel_metrics() symbol. The actual metrics
 * are now sourced from the kernel FIPC core.
 */

#include "fipc_sys.h"

#include <kernel/fut_fipc.h>

bool fipc_sys_publish_kernel_metrics(void) {
    struct fut_fipc_channel *sys = fut_fipc_channel_lookup(FIPC_SYS_CHANNEL_ID);
    if (!sys) {
        if (fut_fipc_channel_create(NULL,
                                    NULL,
                                    4096,
                                    FIPC_CHANNEL_NONBLOCKING,
                                    &sys) != 0 || !sys) {
            return false;
        }
        sys->id = FIPC_SYS_CHANNEL_ID;
        sys->type = FIPC_CHANNEL_SYSTEM;
    }
    return fut_fipc_publish_kernel_metrics() == 0;
}

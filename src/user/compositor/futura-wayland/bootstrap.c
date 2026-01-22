// SPDX-License-Identifier: MPL-2.0

#include <user/sys.h>

__attribute__((constructor))
static void fut_wayland_bootstrap_ctor(void) {
    const char msg[] = "[COMPOSITOR-BOOT] ctor reached\n";
    sys_write(1, msg, (long)(sizeof(msg) - 1));
}

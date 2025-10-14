#include "comp.h"
#include "log.h"
#include "output.h"
#include "shm_backend.h"
#include "xdg_shell.h"

#include <wayland-server-core.h>

#include <user/stdio.h>

int main(void) {
    struct compositor_state comp = {0};

    comp.display = wl_display_create();
    if (!comp.display) {
        printf("[WAYLAND] failed to create wl_display\n");
        return -1;
    }

    comp.loop = wl_display_get_event_loop(comp.display);

    if (comp_state_init(&comp) != 0) {
        wl_display_destroy(comp.display);
        return -1;
    }

    wl_display_init_shm(comp.display);

    if (compositor_global_init(&comp) != 0 ||
        xdg_shell_global_init(&comp) != 0 ||
        output_global_init(&comp) != 0 ||
        shm_backend_init(&comp) != 0) {
        printf("[WAYLAND] failed to initialise globals\n");
        comp_state_finish(&comp);
        wl_display_destroy(comp.display);
        return -1;
    }

    const char *socket = wl_display_add_socket_auto(comp.display);
    if (!socket) {
        printf("[WAYLAND] failed to add display socket\n");
        shm_backend_finish(&comp);
        comp_state_finish(&comp);
        wl_display_destroy(comp.display);
        return -1;
    }

    char ready_buf[128];
    int ready_len = snprintf(ready_buf, sizeof(ready_buf),
                             "[WAYLAND] compositor ready %ux%u bpp=%u socket=%s\n",
                             comp.fb_info.width,
                             comp.fb_info.height,
                             comp.fb_info.bpp,
                             socket);
    if (ready_len > 0) {
        sys_write(1, ready_buf, (long)ready_len);
        sys_write(2, ready_buf, (long)ready_len);
    }

    comp_run(&comp);

    shm_backend_finish(&comp);
    comp_state_finish(&comp);
    wl_display_destroy(comp.display);
    return 0;
}

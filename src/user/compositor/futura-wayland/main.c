#include "comp.h"
#include "log.h"
#include "output.h"
#include "seat.h"
#include "shm_backend.h"
#include "xdg_shell.h"

#include <wayland-server-core.h>
#include <user/stdio.h>
#include <user/stdlib.h>
#include <user/string.h>

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

    const char *multi_env = getenv("WAYLAND_MULTI");
    if (!multi_env) {
        comp.multi_enabled = true;
    } else {
        comp.multi_enabled = (strcmp(multi_env, "0") != 0);
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

    comp.seat = seat_init(&comp);
    if (!comp.seat) {
        printf("[WAYLAND] failed to initialise seat\n");
        shm_backend_finish(&comp);
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

    printf("[WAYLAND] compositor ready %ux%u bpp=%u socket=%s\n",
           comp.fb_info.width,
           comp.fb_info.height,
           comp.fb_info.bpp,
           socket);

    comp_request_repaint(&comp, NULL);
    comp_run(&comp);

    shm_backend_finish(&comp);
    seat_finish(comp.seat);
    comp.seat = NULL;
    comp_state_finish(&comp);
    wl_display_destroy(comp.display);
    return 0;
}

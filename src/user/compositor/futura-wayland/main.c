#include "comp.h"
#include "log.h"
#include "output.h"
#include "seat.h"
#include "shm_backend.h"
#include "data_device.h"
#include "xdg_shell.h"

#include <wayland-server-core.h>
#include <stdbool.h>
#include <errno.h>
#include <user/stdio.h>
#include <user/stdlib.h>

/* Direct syscall wrappers to avoid header conflicts */
#define __NR_open  2
#define __NR_write 1
#define O_RDWR     0x0002

static inline long syscall3(long nr, long arg1, long arg2, long arg3) {
    long ret;
    __asm__ __volatile__(
        "int $0x80\n"
        : "=a"(ret)
        : "a"(nr), "D"(arg1), "S"(arg2), "d"(arg3)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline int sys_open(const char *pathname, int flags, int mode) {
    return (int)syscall3(__NR_open, (long)pathname, flags, mode);
}

static inline long sys_write(int fd, const void *buf, size_t count) {
    return syscall3(__NR_write, fd, (long)buf, count);
}

int main(void) {
    /* Initialize stdio by opening /dev/console for fds 0,1,2 */
    sys_open("/dev/console", O_RDWR, 0);  /* FD 0 - stdin */
    sys_open("/dev/console", O_RDWR, 0);  /* FD 1 - stdout */
    sys_open("/dev/console", O_RDWR, 0);  /* FD 2 - stderr */

    /* Direct write to verify execution */
    const char msg[] = "[COMPOSITOR] Reached main, stdio initialized\n";
    sys_write(1, msg, sizeof(msg) - 1);

    struct compositor_state comp = {0};

    const char *bb_env = getenv("WAYLAND_BACKBUFFER");
    bool want_backbuffer = true;
    if (bb_env && bb_env[0] == '0' && bb_env[1] == '\0') {
        want_backbuffer = false;
    }

    const char *deco_env = getenv("WAYLAND_DECO");
    bool want_deco = true;
    if (deco_env && deco_env[0] == '0' && deco_env[1] == '\0') {
        want_deco = false;
    }

    const char *shadow_env = getenv("WAYLAND_SHADOW");
    bool want_shadow = true;
    if (shadow_env && shadow_env[0] == '0' && shadow_env[1] == '\0') {
        want_shadow = false;
    }

    const char *resize_env = getenv("WAYLAND_RESIZE");
    bool want_resize = true;
    if (resize_env && resize_env[0] == '0' && resize_env[1] == '\0') {
        want_resize = false;
    }

    const char *throttle_env = getenv("WAYLAND_THROTTLE");
    bool want_throttle = true;
    if (throttle_env && throttle_env[0] == '0' && throttle_env[1] == '\0') {
        want_throttle = false;
    }

    comp.backbuffer_enabled = want_backbuffer;
    comp.deco_enabled = want_deco;
    comp.shadow_enabled = want_shadow;
    comp.shadow_radius = want_shadow ? WINDOW_SHADOW_DEFAULT : 0;
    comp.resize_enabled = want_resize;
    comp.throttle_enabled = want_throttle;

    printf("[WAYLAND-DEBUG] About to call comp_state_init()...\n");
    if (comp_state_init(&comp) != 0) {
        printf("[WAYLAND] ERROR: comp_state_init() failed\n");
        return -1;
    }
    printf("[WAYLAND-DEBUG] comp_state_init() succeeded\n");

    printf("[WAYLAND-DEBUG] About to call wl_display_create()...\n");
    comp.display = wl_display_create();
    printf("[WAYLAND-DEBUG] wl_display_create() returned: %p\n", (void *)comp.display);
    if (!comp.display) {
        printf("[WAYLAND] failed to create wl_display\n");
        comp_state_finish(&comp);
        return -1;
    }
    printf("[WAYLAND-DEBUG] wl_display successfully created\n");

    comp.loop = wl_display_get_event_loop(comp.display);

    if (comp_set_backbuffer_enabled(&comp, want_backbuffer) != 0) {
        printf("[WAYLAND] warning: backbuffer setup failed, falling back to direct FB\n");
        comp_set_backbuffer_enabled(&comp, false);
    }
    comp.last_present_ns = 0;

    const char *multi_env = getenv("WAYLAND_MULTI");
    if (!multi_env || !(multi_env[0] == '0' && multi_env[1] == '\0')) {
        comp.multi_enabled = true;
    } else {
        comp.multi_enabled = false;
    }

    wl_display_init_shm(comp.display);

    printf("[WAYLAND-DEBUG] Initializing compositor global...\n");
    if (compositor_global_init(&comp) != 0) {
        printf("[WAYLAND] compositor_global_init FAILED\n");
        comp_state_finish(&comp);
        wl_display_destroy(comp.display);
        return -1;
    }
    printf("[WAYLAND-DEBUG] compositor_global_init OK\n");

    printf("[WAYLAND-DEBUG] Initializing xdg_shell global...\n");
    if (xdg_shell_global_init(&comp) != 0) {
        printf("[WAYLAND] xdg_shell_global_init FAILED\n");
        comp_state_finish(&comp);
        wl_display_destroy(comp.display);
        return -1;
    }
    printf("[WAYLAND-DEBUG] xdg_shell_global_init OK\n");

    printf("[WAYLAND-DEBUG] Initializing output global...\n");
    if (output_global_init(&comp) != 0) {
        printf("[WAYLAND] output_global_init FAILED\n");
        comp_state_finish(&comp);
        wl_display_destroy(comp.display);
        return -1;
    }
    printf("[WAYLAND-DEBUG] output_global_init OK\n");

    printf("[WAYLAND-DEBUG] Initializing shm backend...\n");
    if (shm_backend_init(&comp) != 0) {
        printf("[WAYLAND] shm_backend_init FAILED\n");
        comp_state_finish(&comp);
        wl_display_destroy(comp.display);
        return -1;
    }
    printf("[WAYLAND-DEBUG] shm_backend_init OK\n");

    printf("[WAYLAND-DEBUG] Initializing data_device_manager...\n");
    if (data_device_manager_init(&comp) != 0) {
        printf("[WAYLAND] data_device_manager_init FAILED\n");
        comp_state_finish(&comp);
        wl_display_destroy(comp.display);
        return -1;
    }
    printf("[WAYLAND-DEBUG] data_device_manager_init OK\n");

    comp.seat = seat_init(&comp);
    if (!comp.seat) {
        printf("[WAYLAND] failed to initialise seat\n");
        data_device_manager_finish(&comp);
        shm_backend_finish(&comp);
        comp_state_finish(&comp);
        wl_display_destroy(comp.display);
        return -1;
    }

    if (comp_scheduler_start(&comp) != 0) {
        printf("[WAYLAND] failed to start frame scheduler\n");
        seat_finish(comp.seat);
        data_device_manager_finish(&comp);
        shm_backend_finish(&comp);
        comp_state_finish(&comp);
        wl_display_destroy(comp.display);
        return -1;
    }

    /* Ensure XDG_RUNTIME_DIR is set for Wayland socket creation */
    if (!getenv("XDG_RUNTIME_DIR")) {
        printf("[WAYLAND-DEBUG] Setting XDG_RUNTIME_DIR=/tmp\n");
        setenv("XDG_RUNTIME_DIR", "/tmp", 1);
    }

    const char *socket = wl_display_add_socket_auto(comp.display);
    if (!socket) {
        printf("[WAYLAND] failed to add_socket_auto (errno=%d)\n", errno);
        /* Try manual socket name as fallback */
        int rc = wl_display_add_socket(comp.display, "wayland-0");
        if (rc < 0) {
            printf("[WAYLAND] failed to add manual socket (rc=%d, errno=%d)\n", rc, errno);
            data_device_manager_finish(&comp);
            shm_backend_finish(&comp);
            comp_state_finish(&comp);
            wl_display_destroy(comp.display);
            return -1;
        }
        socket = "wayland-0";
        printf("[WAYLAND-DEBUG] Using manual socket: %s\n", socket);
    }

    printf("[WAYLAND] compositor ready %ux%u bpp=%u socket=%s\n",
           comp.fb_info.width,
           comp.fb_info.height,
           comp.fb_info.bpp,
           socket);

    comp_damage_add_full(&comp);
    comp_render_frame(&comp);
    comp_run(&comp);

    shm_backend_finish(&comp);
    data_device_manager_finish(&comp);
    seat_finish(comp.seat);
    comp.seat = NULL;
    comp_state_finish(&comp);
    wl_display_destroy(comp.display);
    return 0;
}

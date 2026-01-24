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
#include <string.h>
#include <fcntl.h>
#include <user/stdio.h>
#include <user/stdlib.h>

/* Portable syscall wrappers using libfutura */
#include "syscall_portable.h"

/* Additional syscall numbers not in syscall_portable.h */
#define __NR_mkdir 83

static inline int sys_open(const char *pathname, int flags, int mode) {
    return (int)syscall3(__NR_open, (long)pathname, flags, mode);
}

static inline long sys_write(int fd, const void *buf, size_t count) {
    return syscall3(__NR_write, fd, (long)buf, count);
}

static inline int sys_close(int fd) {
    return (int)syscall1(__NR_close, fd);
}

static inline int sys_mkdir(const char *pathname, int mode) {
    return (int)syscall2(__NR_mkdir, (long)pathname, mode);
}

/* Helper: Test if directory is writable for sockets */
static int test_socket_directory(const char *path) {
    int fd = sys_open(path, 0, 0);
    if (fd < 0) {
        return 0;
    }
    sys_close(fd);

    char test_path[512];
    snprintf(test_path, sizeof(test_path), "%s/.wayland-test", path);

    int test_fd = sys_open(test_path, O_RDWR | O_CREAT, 0666);
    if (test_fd < 0) {
        return 0;
    }
    sys_close(test_fd);
    return 1;
}

/* Helper: Find first writable directory for Wayland sockets */
static const char *find_working_runtime_dir(void) {
    const char *candidates[] = { "/tmp", "/run", "/var/run", "/dev/shm", NULL };

    for (int i = 0; candidates[i]; i++) {
        if (test_socket_directory(candidates[i])) {
            return candidates[i];
        }
    }
    return "/tmp";
}

static void write_ready_marker(const char *runtime_dir, const char *socket) {
    if (!runtime_dir || !socket || socket[0] == '\0' || strcmp(socket, "none") == 0) {
        return;
    }

    char ready_path[256];
    snprintf(ready_path, sizeof(ready_path), "%s/wayland-ready", runtime_dir);

    int fd = sys_open(ready_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        return;
    }

    char buf[128];
    int len = snprintf(buf, sizeof(buf), "socket=%s\n", socket);
    if (len > 0) {
        sys_write(fd, buf, (size_t)len);
    }
    sys_close(fd);
}

int main(void) {
    sys_mkdir("/tmp", 0777);

    struct compositor_state comp = {0};

    const char *bb_env = getenv("WAYLAND_BACKBUFFER");
    bool want_backbuffer = false; /* Heap allocator struggles with double 3 MiB buffers */
    if (bb_env && bb_env[0] == '1' && bb_env[1] == '\0') {
        want_backbuffer = true;
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

    if (comp_state_init(&comp) != 0) {
        printf("[WAYLAND] comp_state_init failed\n");
        return -1;
    }

    comp.display = wl_display_create();
    if (!comp.display) {
        printf("[WAYLAND] wl_display_create failed\n");
        comp_state_finish(&comp);
        return -1;
    }

    comp.loop = wl_display_get_event_loop(comp.display);

    if (comp_set_backbuffer_enabled(&comp, want_backbuffer) != 0) {
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

    if (compositor_global_init(&comp) != 0 ||
        xdg_shell_global_init(&comp) != 0 ||
        output_global_init(&comp) != 0 ||
        shm_backend_init(&comp) != 0 ||
        data_device_manager_init(&comp) != 0) {
        comp_state_finish(&comp);
        wl_display_destroy(comp.display);
        return -1;
    }

    comp.seat = seat_init(&comp);
    if (!comp.seat) {
        comp_state_finish(&comp);
        wl_display_destroy(comp.display);
        return -1;
    }

    if (comp_scheduler_start(&comp) != 0) {
        seat_finish(comp.seat);
        comp_state_finish(&comp);
        wl_display_destroy(comp.display);
        return -1;
    }

    if (!getenv("XDG_RUNTIME_DIR")) {
        const char *runtime_dir = find_working_runtime_dir();
        setenv("XDG_RUNTIME_DIR", runtime_dir, 1);
    }

    const char *runtime_dir = getenv("XDG_RUNTIME_DIR");
    errno = 0;

    const char *socket = wl_display_add_socket_auto(comp.display);
    if (!socket) {
        errno = 0;
        int rc = wl_display_add_socket(comp.display, "wayland-0");
        if (rc < 0) {
            socket = "none";
        } else {
            socket = "wayland-0";
        }
    }

    write_ready_marker(runtime_dir, socket);

    printf("[WAYLAND] ready %ux%u socket=%s\n",
           comp.fb_info.width,
           comp.fb_info.height,
           socket);

    /* Demo mode: render test pattern when socket creation fails */
    if (!socket || strcmp(socket, "none") == 0) {
        comp_scheduler_stop(&comp);
        comp_render_demo_frame(&comp);
        while (1) {
            volatile int x = 0;
            x++;
        }
    } else {
        /* Normal mode */
        comp_damage_add_full(&comp);
        comp_render_frame(&comp);
        comp_run(&comp);
    }

    shm_backend_finish(&comp);
    data_device_manager_finish(&comp);
    seat_finish(comp.seat);
    comp.seat = NULL;
    comp_state_finish(&comp);
    wl_display_destroy(comp.display);
    return 0;
}

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
#include <user/stdio.h>
#include <user/stdlib.h>

/* Direct syscall wrappers to avoid header conflicts */
#define __NR_open  2
#define __NR_write 1
#define __NR_close 3
#define __NR_mkdir 39
#define O_RDWR     0x0002
#define O_CREAT    0x0040

static inline long syscall3(long nr, long arg1, long arg2, long arg3) {
    /* Use x86-64 calling convention for int 0x80 (RAX=syscall, RDI=arg1, RSI=arg2, RDX=arg3)
     * This matches what the kernel's isr_stubs.S expects when extracting arguments */
    long result;
    __asm__ volatile(
        "int $0x80"
        : "=a"(result)
        : "a"(nr), "D"(arg1), "S"(arg2), "d"(arg3)
        : "memory", "rcx", "r11"
    );
    return result;
}

static inline long syscall1(long nr, long arg1) {
    /* Use x86-64 calling convention for int 0x80 (RAX=syscall, RDI=arg1)
     * This matches what the kernel's isr_stubs.S expects when extracting arguments */
    long result;
    __asm__ volatile(
        "int $0x80"
        : "=a"(result)
        : "a"(nr), "D"(arg1)
        : "memory", "rcx", "r11"
    );
    return result;
}

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
    return (int)syscall3(__NR_mkdir, (long)pathname, mode, 0);
}

/* Helper: Test if directory is writable for sockets */
static int test_socket_directory(const char *path) {
    /* Test 1: Can we access the directory? */
    printf("[WAYLAND-DEBUG] Testing directory: %s\n", path);

    int fd = sys_open(path, 0, 0);
    if (fd < 0) {
        printf("[WAYLAND-DEBUG]   Not accessible\n");
        return 0;
    }
    sys_close(fd);
    printf("[WAYLAND-DEBUG]   Accessible\n");

    /* Test 2: Can we create a file there? */
    char test_path[512];
    snprintf(test_path, sizeof(test_path), "%s/.wayland-test", path);

    int test_fd = sys_open(test_path, O_RDWR | O_CREAT, 0666);
    if (test_fd < 0) {
        printf("[WAYLAND-DEBUG]   Not writable\n");
        return 0;
    }
    sys_close(test_fd);
    printf("[WAYLAND-DEBUG]   Writable - GOOD!\n");

    return 1;
}

/* Helper: Find first writable directory for Wayland sockets */
static const char *find_working_runtime_dir(void) {
    const char *candidates[] = {
        "/tmp",
        "/run",
        "/var/run",
        "/dev/shm",
        NULL
    };

    printf("[WAYLAND-DEBUG] Finding writable directory for sockets\n");

    for (int i = 0; candidates[i]; i++) {
        if (test_socket_directory(candidates[i])) {
            printf("[WAYLAND-DEBUG] ✓ Using runtime dir: %s\n", candidates[i]);
            return candidates[i];
        }
    }

    /* Last resort */
    printf("[WAYLAND-DEBUG] WARNING: No ideal dir found, using /tmp\n");
    return "/tmp";
}

int main(void) {
    /* Initialize stdio - FDs 0,1,2 should already be open from parent shell
     * Skip opening /dev/console as it may not be accessible in user environment */

    /* Direct write to verify execution */
    const char msg[] = "[COMPOSITOR] Reached main, stdio initialized\n";
    sys_write(1, msg, sizeof(msg) - 1);

    /* Create /tmp directory for Wayland sockets and lock files */
    sys_mkdir("/tmp", 0777);

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

#ifdef DEBUG_WAYLAND
    printf("[WAYLAND-DEBUG] About to call comp_state_init()...\n");
#endif
    if (comp_state_init(&comp) != 0) {
        printf("[WAYLAND] ERROR: comp_state_init() failed\n");
        return -1;
    }
#ifdef DEBUG_WAYLAND
    printf("[WAYLAND-DEBUG] comp_state_init() succeeded\n");
#endif

#ifdef DEBUG_WAYLAND
    printf("[WAYLAND-DEBUG] About to call wl_display_create()...\n");
#endif
    comp.display = wl_display_create();
#ifdef DEBUG_WAYLAND
    printf("[WAYLAND-DEBUG] wl_display_create() returned: %p\n", (void *)comp.display);
#endif
    if (!comp.display) {
        printf("[WAYLAND] failed to create wl_display\n");
        comp_state_finish(&comp);
        return -1;
    }
#ifdef DEBUG_WAYLAND
    printf("[WAYLAND-DEBUG] wl_display successfully created\n");
#endif

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

#ifdef DEBUG_WAYLAND
    printf("[WAYLAND-DEBUG] Initializing compositor global...\n");
#endif
    if (compositor_global_init(&comp) != 0) {
        printf("[WAYLAND] compositor_global_init FAILED\n");
        comp_state_finish(&comp);
        wl_display_destroy(comp.display);
        return -1;
    }
#ifdef DEBUG_WAYLAND
    printf("[WAYLAND-DEBUG] compositor_global_init OK\n");
#endif

#ifdef DEBUG_WAYLAND
    printf("[WAYLAND-DEBUG] Initializing xdg_shell global...\n");
#endif
    if (xdg_shell_global_init(&comp) != 0) {
        printf("[WAYLAND] xdg_shell_global_init FAILED\n");
        comp_state_finish(&comp);
        wl_display_destroy(comp.display);
        return -1;
    }
#ifdef DEBUG_WAYLAND
    printf("[WAYLAND-DEBUG] xdg_shell_global_init OK\n");
#endif

#ifdef DEBUG_WAYLAND
    printf("[WAYLAND-DEBUG] Initializing output global...\n");
#endif
    if (output_global_init(&comp) != 0) {
        printf("[WAYLAND] output_global_init FAILED\n");
        comp_state_finish(&comp);
        wl_display_destroy(comp.display);
        return -1;
    }
#ifdef DEBUG_WAYLAND
    printf("[WAYLAND-DEBUG] output_global_init OK\n");
#endif

#ifdef DEBUG_WAYLAND
    printf("[WAYLAND-DEBUG] Initializing shm backend...\n");
#endif
    if (shm_backend_init(&comp) != 0) {
        printf("[WAYLAND] shm_backend_init FAILED\n");
        comp_state_finish(&comp);
        wl_display_destroy(comp.display);
        return -1;
    }
#ifdef DEBUG_WAYLAND
    printf("[WAYLAND-DEBUG] shm_backend_init OK\n");
#endif

#ifdef DEBUG_WAYLAND
    printf("[WAYLAND-DEBUG] Initializing data_device_manager...\n");
#endif
    if (data_device_manager_init(&comp) != 0) {
        printf("[WAYLAND] data_device_manager_init FAILED\n");
        comp_state_finish(&comp);
        wl_display_destroy(comp.display);
        return -1;
    }
#ifdef DEBUG_WAYLAND
    printf("[WAYLAND-DEBUG] data_device_manager_init OK\n");
#endif

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
        /* Find a working directory for Wayland sockets */
        const char *runtime_dir = find_working_runtime_dir();
        setenv("XDG_RUNTIME_DIR", runtime_dir, 1);
    }

    /* Clear errno before socket creation to avoid stale values */
    printf("[WAYLAND-DEBUG] About to clear errno and create socket\n");
    printf("[WAYLAND-DEBUG] XDG_RUNTIME_DIR=%s\n", getenv("XDG_RUNTIME_DIR"));

    /* Verify XDG_RUNTIME_DIR is accessible */
    const char *runtime_dir = getenv("XDG_RUNTIME_DIR");
    /* Try to access the directory by opening it - simpler than stat() */
    int runtime_dir_fd = sys_open(runtime_dir, 0, 0);
    if (runtime_dir_fd < 0) {
        printf("[WAYLAND-DEBUG] WARNING: XDG_RUNTIME_DIR not accessible: %s\n",
               runtime_dir);
    } else {
        printf("[WAYLAND-DEBUG] XDG_RUNTIME_DIR accessible\n");
        sys_close(runtime_dir_fd);
    }

    errno = 0;
    // Do NOT call printf here - it may set errno!

    printf("[WAYLAND-DEBUG] Calling wl_display_add_socket_auto()\n");
    printf("[WAYLAND-DEBUG] Environment: WAYLAND_DISPLAY=%s\n", getenv("WAYLAND_DISPLAY"));
    printf("[WAYLAND-DEBUG] Temp file check: touching test file in %s\n", runtime_dir);

    /* Quick sanity check - try to create a test file in runtime_dir */
    char test_file[256];
    snprintf(test_file, sizeof(test_file), "%s/.wayland-test", runtime_dir);
    int test_fd = sys_open(test_file, O_RDWR | O_CREAT, 0666);
    if (test_fd >= 0) {
        printf("[WAYLAND-DEBUG] Test file created successfully\n");
        sys_close(test_fd);
    } else {
        printf("[WAYLAND-DEBUG] WARNING: Could not create test file (may indicate permission issues)\n");
    }

    const char *socket = wl_display_add_socket_auto(comp.display);
    // Save errno immediately before printf can corrupt it
    int saved_errno = errno;
    printf("[WAYLAND-DEBUG] After add_socket_auto, socket=%p errno=%d (%s)\n",
           (void*)socket, saved_errno, strerror(saved_errno));

    if (socket) {
        printf("[WAYLAND] SUCCESS: auto socket created: %s\n", socket);

        /* Verify socket file was created by trying to open it */
        char socket_path[256];
        snprintf(socket_path, sizeof(socket_path), "%s/%s", runtime_dir, socket);
        int socket_fd = sys_open(socket_path, 0, 0);
        if (socket_fd >= 0) {
            printf("[WAYLAND-DEBUG] Socket file verified at: %s\n", socket_path);
            sys_close(socket_fd);
        } else {
            printf("[WAYLAND-DEBUG] WARNING: Socket file not found at: %s\n", socket_path);
        }
    } else {
        printf("[WAYLAND-DEBUG] add_socket_auto failed with errno=%d, trying manual socket\n", saved_errno);

        /* Try manual socket name as fallback */
        printf("[WAYLAND-DEBUG] Attempting wl_display_add_socket(display, 'wayland-0')\n");
        errno = 0;
        int rc = wl_display_add_socket(comp.display, "wayland-0");
        int manual_errno = errno;
        printf("[WAYLAND-DEBUG] wl_display_add_socket returned rc=%d, errno=%d (%s)\n",
               rc, manual_errno, strerror(manual_errno));

        if (rc < 0) {
            printf("[WAYLAND] warning: add manual socket also failed (rc=%d, errno=%d), continuing without socket\n",
                   rc, manual_errno);
            socket = "none";
        } else {
            socket = "wayland-0";
            printf("[WAYLAND-DEBUG] Using manual socket: %s\n", socket);

            /* Verify socket file was created by trying to open it */
            char socket_path[256];
            snprintf(socket_path, sizeof(socket_path), "%s/%s", runtime_dir, socket);
            int socket_fd = sys_open(socket_path, 0, 0);
            if (socket_fd >= 0) {
                printf("[WAYLAND-DEBUG] Socket file verified at: %s\n", socket_path);
                sys_close(socket_fd);
            } else {
                printf("[WAYLAND-DEBUG] WARNING: Socket file not found at: %s\n", socket_path);
            }
        }
    }

    printf("[WAYLAND] compositor ready %ux%u bpp=%u socket=%s\n",
           comp.fb_info.width,
           comp.fb_info.height,
           comp.fb_info.bpp,
           socket);

    /* Demo mode: render test pattern when socket creation fails */
    if (!socket || strcmp(socket, "none") == 0) {
        printf("[WAYLAND] Demo mode: socket creation failed, rendering test pattern\n");
        printf("[WAYLAND] fb_map address: %p\n", (void*)comp.fb_map);

        /* Stop the scheduler to prevent it from clearing our demo frame */
        comp_scheduler_stop(&comp);
        printf("[WAYLAND] Frame scheduler stopped for demo mode\n");

        /* Render the demo pattern */
        comp_render_demo_frame(&comp);

        /* In demo mode, just render once and then idle - no client connections possible */
        printf("[WAYLAND] Demo mode complete - compositor idle (waiting for system reset)\n");
        while (1) {
            /* Infinite loop: compositor is alive but has no clients */
            volatile int x = 0;
            x++;  /* Prevent optimizer from removing the loop */
        }
    } else {
        /* Normal mode: render initial frame with damage and run compositor */
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

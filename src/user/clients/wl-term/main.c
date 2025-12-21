/* main.c - Wayland terminal emulator
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * A simple terminal emulator that displays a shell in a Wayland window.
 * Uses fork/exec to spawn the shell and pipes for I/O.
 */

#include "terminal.h"
#include "font.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <futura/compat/posix_shm.h>
#include <user/stdio.h>
#include <user/sys.h>

#include <wayland-client-core.h>
#include <wayland-client-protocol.h>
#include "xdg-shell-client-protocol.h"

/* Terminal window size (80x25 chars = 640x400 pixels) */
#define TERM_WIDTH  (TERM_COLS * FONT_WIDTH)
#define TERM_HEIGHT (TERM_ROWS * FONT_HEIGHT)

#define O_RDWR      0x0002
#define O_CREAT     0x0040
#define O_TRUNC     0x0200
#define PROT_READ   0x0001
#define PROT_WRITE  0x0002
#define MAP_SHARED  0x0001

/* Client state */
struct client_state {
    /* Wayland objects */
    struct wl_display *display;
    struct wl_registry *registry;
    struct wl_compositor *compositor;
    struct wl_shm *shm;
    struct xdg_wm_base *xdg_wm_base;
    struct wl_seat *seat;
    struct wl_keyboard *keyboard;
    struct wl_surface *surface;
    struct xdg_surface *xdg_surface;
    struct xdg_toplevel *toplevel;

    /* Configuration state */
    bool configured;
    uint32_t configure_serial;

    /* Frame tracking */
    struct wl_callback *frame_cb;
    bool frame_done;
    bool needs_redraw;

    /* Buffer management */
    void *shm_data;
    size_t shm_size;
    int shm_fd;
    struct wl_buffer *buffer;

    /* Terminal emulator */
    struct terminal term;

    /* Running state */
    bool running;
};

/* XDG WM Base listener */
static void handle_ping(void *data, struct xdg_wm_base *wm_base, uint32_t serial) {
    (void)data;
    xdg_wm_base_pong(wm_base, serial);
}

static const struct xdg_wm_base_listener wm_base_listener = {
    .ping = handle_ping,
};

/* XDG Surface listener */
static void xdg_surface_configure(void *data, struct xdg_surface *surface, uint32_t serial) {
    (void)surface;
    struct client_state *state = data;
    state->configure_serial = serial;
    state->configured = true;
}

static const struct xdg_surface_listener xdg_surface_listener = {
    .configure = xdg_surface_configure,
};

/* XDG Toplevel listener */
static void xdg_toplevel_configure(void *data, struct xdg_toplevel *toplevel,
                                   int32_t width, int32_t height, struct wl_array *states) {
    (void)data; (void)toplevel; (void)width; (void)height; (void)states;
}

static void xdg_toplevel_close(void *data, struct xdg_toplevel *toplevel) {
    (void)toplevel;
    struct client_state *state = data;
    state->running = false;
}

static const struct xdg_toplevel_listener xdg_toplevel_listener = {
    .configure = xdg_toplevel_configure,
    .close = xdg_toplevel_close,
};

/* Keyboard listener */
static void keyboard_keymap(void *data, struct wl_keyboard *keyboard,
                           uint32_t format, int32_t fd, uint32_t size) {
    (void)data; (void)keyboard; (void)format; (void)size;
    if (fd >= 0) {
        sys_close(fd);
    }
}

static void keyboard_enter(void *data, struct wl_keyboard *keyboard, uint32_t serial,
                          struct wl_surface *surface, struct wl_array *keys) {
    (void)data; (void)keyboard; (void)serial; (void)surface; (void)keys;
}

static void keyboard_leave(void *data, struct wl_keyboard *keyboard, uint32_t serial,
                          struct wl_surface *surface) {
    (void)data; (void)keyboard; (void)serial; (void)surface;
}

/* Simple keycode to ASCII mapping (US keyboard layout) */
static char keycode_to_ascii(uint32_t key, bool shift) {
    /* Evdev keycodes - simplified mapping */
    if (key >= 2 && key <= 11) {  /* Number row */
        if (!shift) {
            const char nums[] = "1234567890";
            return nums[key - 2];
        } else {
            const char syms[] = "!@#$%^&*()";
            return syms[key - 2];
        }
    }

    if (key >= 16 && key <= 25) {  /* QWERTYUIOP */
        const char keys[] = "qwertyuiop";
        char ch = keys[key - 16];
        return shift ? (ch - 32) : ch;
    }

    if (key >= 30 && key <= 38) {  /* ASDFGHJKL */
        const char keys[] = "asdfghjkl";
        char ch = keys[key - 30];
        return shift ? (ch - 32) : ch;
    }

    if (key >= 44 && key <= 50) {  /* ZXCVBNM */
        const char keys[] = "zxcvbnm";
        char ch = keys[key - 44];
        return shift ? (ch - 32) : ch;
    }

    switch (key) {
        case 28: return '\n';       /* Enter */
        case 57: return ' ';        /* Space */
        case 14: return '\b';       /* Backspace */
        case 15: return '\t';       /* Tab */
        case 12: return shift ? '_' : '-';  /* Minus */
        case 13: return shift ? '+' : '=';  /* Equals */
        case 26: return shift ? '{' : '[';  /* Left bracket */
        case 27: return shift ? '}' : ']';  /* Right bracket */
        case 39: return shift ? ':' : ';';  /* Semicolon */
        case 40: return shift ? '"' : '\''; /* Quote */
        case 41: return shift ? '~' : '`';  /* Backtick */
        case 43: return shift ? '|' : '\\'; /* Backslash */
        case 51: return shift ? '<' : ',';  /* Comma */
        case 52: return shift ? '>' : '.';  /* Period */
        case 53: return shift ? '?' : '/';  /* Slash */
        default: return 0;
    }
}

static void keyboard_key(void *data, struct wl_keyboard *keyboard, uint32_t serial,
                        uint32_t time, uint32_t key, uint32_t key_state) {
    (void)keyboard; (void)serial; (void)time;

    struct client_state *state = data;
    if (!state || key_state != WL_KEYBOARD_KEY_STATE_PRESSED) {
        return;
    }

    /* Convert keycode to ASCII (assuming no modifiers for simplicity) */
    char ch = keycode_to_ascii(key, false);
    if (ch != 0) {
        term_send_key(&state->term, ch);
    }
}

static void keyboard_modifiers(void *data, struct wl_keyboard *keyboard, uint32_t serial,
                              uint32_t mods_depressed, uint32_t mods_latched,
                              uint32_t mods_locked, uint32_t group) {
    (void)data; (void)keyboard; (void)serial;
    (void)mods_depressed; (void)mods_latched; (void)mods_locked; (void)group;
}

static void keyboard_repeat(void *data, struct wl_keyboard *keyboard,
                           int32_t rate, int32_t delay) {
    (void)data; (void)keyboard; (void)rate; (void)delay;
}

static const struct wl_keyboard_listener keyboard_listener = {
    .keymap = keyboard_keymap,
    .enter = keyboard_enter,
    .leave = keyboard_leave,
    .key = keyboard_key,
    .modifiers = keyboard_modifiers,
    .repeat_info = keyboard_repeat,
};

/* Seat listener */
static void seat_capabilities(void *data, struct wl_seat *seat, uint32_t capabilities) {
    struct client_state *state = data;
    if (!state) {
        return;
    }

    bool want_keyboard = (capabilities & WL_SEAT_CAPABILITY_KEYBOARD) != 0;
    if (want_keyboard && !state->keyboard) {
        state->keyboard = wl_seat_get_keyboard(seat);
        if (state->keyboard) {
            wl_keyboard_add_listener(state->keyboard, &keyboard_listener, state);
        }
    } else if (!want_keyboard && state->keyboard) {
        wl_keyboard_destroy(state->keyboard);
        state->keyboard = NULL;
    }
}

static void seat_name(void *data, struct wl_seat *seat, const char *name) {
    (void)data; (void)seat; (void)name;
}

static const struct wl_seat_listener seat_listener = {
    .capabilities = seat_capabilities,
    .name = seat_name,
};

/* Registry listener */
static void registry_global(void *data, struct wl_registry *registry, uint32_t name,
                           const char *interface, uint32_t version) {
    struct client_state *state = data;

    printf("[WL-TERM-REGISTRY] Global advertised: name=%u interface=%s version=%u\n",
           name, interface, version);

    if (strcmp(interface, wl_compositor_interface.name) == 0) {
        uint32_t ver = version < 4 ? version : 4;
        state->compositor = wl_registry_bind(registry, name, &wl_compositor_interface, ver);
        printf("[WL-TERM-REGISTRY] Bound wl_compositor: %p\n", state->compositor);
    } else if (strcmp(interface, wl_shm_interface.name) == 0) {
        state->shm = wl_registry_bind(registry, name, &wl_shm_interface, 1);
        printf("[WL-TERM-REGISTRY] Bound wl_shm: %p\n", state->shm);
    } else if (strcmp(interface, xdg_wm_base_interface.name) == 0) {
        uint32_t ver = version < 2 ? version : 2;
        state->xdg_wm_base = wl_registry_bind(registry, name, &xdg_wm_base_interface, ver);
        printf("[WL-TERM-REGISTRY] Bound xdg_wm_base: %p\n", state->xdg_wm_base);
        xdg_wm_base_add_listener(state->xdg_wm_base, &wm_base_listener, state);
    } else if (strcmp(interface, wl_seat_interface.name) == 0) {
        uint32_t ver = version < 7 ? version : 7;
        state->seat = wl_registry_bind(registry, name, &wl_seat_interface, ver);
        if (state->seat) {
            wl_seat_add_listener(state->seat, &seat_listener, state);
        }
        printf("[WL-TERM-REGISTRY] Bound wl_seat: %p\n", state->seat);
    } else {
        printf("[WL-TERM-REGISTRY] Unknown global: %s\n", interface);
    }
}

static void registry_global_remove(void *data, struct wl_registry *registry, uint32_t name) {
    (void)data; (void)registry; (void)name;
}

static const struct wl_registry_listener registry_listener = {
    .global = registry_global,
    .global_remove = registry_global_remove,
};

/* Frame callback */
static void frame_done(void *data, struct wl_callback *callback, uint32_t time) {
    (void)time;
    struct client_state *state = data;
    state->frame_done = true;
    if (state->frame_cb == callback) {
        state->frame_cb = NULL;
    }
    wl_callback_destroy(callback);
}

static const struct wl_callback_listener frame_listener = {
    .done = frame_done,
};

/* Spawn shell process */
static int spawn_shell(struct terminal *term) {
    int stdin_pipe[2], stdout_pipe[2];

    /* Create pipes for shell communication */
    if (sys_pipe_call(stdin_pipe) < 0) {
        printf("[WL-TERM] failed to create stdin pipe\n");
        return -1;
    }

    if (sys_pipe_call(stdout_pipe) < 0) {
        printf("[WL-TERM] failed to create stdout pipe\n");
        sys_close(stdin_pipe[0]);
        sys_close(stdin_pipe[1]);
        return -1;
    }

    /* Fork shell process */
    long pid = sys_fork_call();
    if (pid < 0) {
        printf("[WL-TERM] fork failed\n");
        sys_close(stdin_pipe[0]);
        sys_close(stdin_pipe[1]);
        sys_close(stdout_pipe[0]);
        sys_close(stdout_pipe[1]);
        return -1;
    }

    if (pid == 0) {
        /* Child process - exec shell */

        /* Close unused pipe ends */
        sys_close(stdin_pipe[1]);   /* Close write end of stdin pipe */
        sys_close(stdout_pipe[0]);  /* Close read end of stdout pipe */

        /* Redirect stdin/stdout to pipes */
        sys_dup2_call(stdin_pipe[0], 0);   /* stdin = read end of stdin pipe */
        sys_dup2_call(stdout_pipe[1], 1);  /* stdout = write end of stdout pipe */
        sys_dup2_call(stdout_pipe[1], 2);  /* stderr = write end of stdout pipe */

        /* Close original pipe fds */
        sys_close(stdin_pipe[0]);
        sys_close(stdout_pipe[1]);

        /* Exec shell */
        char shell_name[] = "futura-shell";
        char *shell_args[] = { shell_name, NULL };
        sys_execve_call("/sbin/futura-shell", shell_args, NULL);

        /* If we get here, exec failed */
        const char msg[] = "exec /sbin/futura-shell failed\n";
        sys_write(2, msg, sizeof(msg) - 1);
        sys_exit(1);
    }

    /* Parent process */
    sys_close(stdin_pipe[0]);   /* Close read end of stdin pipe */
    sys_close(stdout_pipe[1]);  /* Close write end of stdout pipe */

    /* Save pipe FDs in terminal state */
    term->shell_stdin_fd = stdin_pipe[1];   /* Write to shell's stdin */
    term->shell_stdout_fd = stdout_pipe[0]; /* Read from shell's stdout */
    term->shell_pid = (int)pid;

    /* Use sys_write instead of printf to avoid potential va_list issues */
    const char spawn_msg[] = "[WL-TERM] Shell spawned\n";
    sys_write(1, spawn_msg, sizeof(spawn_msg) - 1);
    return 0;
}

/* Render terminal to buffer and request frame */
static void redraw(struct client_state *state) {
    if (!state->buffer || !state->shm_data) {
        return;
    }

    /* Render terminal to pixel buffer */
    uint32_t *pixels = (uint32_t *)state->shm_data;
    term_render(&state->term, pixels, TERM_WIDTH, TERM_HEIGHT, TERM_WIDTH);

    /* Request frame callback */
    state->frame_done = false;
    state->frame_cb = wl_surface_frame(state->surface);
    wl_callback_add_listener(state->frame_cb, &frame_listener, state);

    /* Commit surface */
    wl_surface_attach(state->surface, state->buffer, 0, 0);
    wl_surface_damage_buffer(state->surface, 0, 0, TERM_WIDTH, TERM_HEIGHT);
    wl_surface_commit(state->surface);
    wl_display_flush(state->display);

    state->needs_redraw = false;
}

/* Main loop iteration */
static bool main_loop_iteration(struct client_state *state) {
    /* Read from shell if available */
    int n = term_read_shell(&state->term);
    if (n > 0) {
        state->needs_redraw = true;
    } else if (n < 0) {
        /* Shell closed */
        printf("[WL-TERM] Shell exited\n");
        return false;
    }

    /* Redraw if needed and frame is ready */
    if (state->needs_redraw && state->frame_done) {
        redraw(state);
    }

    /* Process Wayland events (non-blocking with short timeout) */
    wl_display_dispatch_pending(state->display);
    wl_display_flush(state->display);

    return state->running;
}

int main(void) {
    printf("[WL-TERM] Starting...\n");
    struct client_state state = {0};
    state.running = true;
    state.frame_done = true;

    printf("[WL-TERM] Initializing terminal...\n");
    /* Initialize terminal */
    term_init(&state.term);

    printf("[WL-TERM] Connecting to Wayland display...\n");
    /* Connect to Wayland display */
    state.display = wl_display_connect(NULL);
    if (!state.display) {
        printf("[WL-TERM] Failed to connect to Wayland\n");
        return -1;
    }
    printf("[WL-TERM] Connected to Wayland!\n");

    /* Get registry and bind globals */
    printf("[WL-TERM] Getting registry...\n");
    state.registry = wl_display_get_registry(state.display);
    wl_registry_add_listener(state.registry, &registry_listener, &state);

    printf("[WL-TERM] About to call wl_display_roundtrip()...\n");
    int roundtrip_result = wl_display_roundtrip(state.display);
    printf("[WL-TERM] wl_display_roundtrip() returned: %d\n", roundtrip_result);
    printf("[WL-TERM] After roundtrip: compositor=%p shm=%p xdg_wm_base=%p\n",
           state.compositor, state.shm, state.xdg_wm_base);

    if (!state.compositor || !state.shm || !state.xdg_wm_base) {
        printf("[WL-TERM] Missing required Wayland globals\n");
        wl_display_disconnect(state.display);
        return -1;
    }

    /* Create surface */
    state.surface = wl_compositor_create_surface(state.compositor);
    if (!state.surface) {
        printf("[WL-TERM] Failed to create surface\n");
        wl_display_disconnect(state.display);
        return -1;
    }

    /* Create XDG surface and toplevel */
    state.xdg_surface = xdg_wm_base_get_xdg_surface(state.xdg_wm_base, state.surface);
    xdg_surface_add_listener(state.xdg_surface, &xdg_surface_listener, &state);

    state.toplevel = xdg_surface_get_toplevel(state.xdg_surface);
    xdg_toplevel_add_listener(state.toplevel, &xdg_toplevel_listener, &state);
    xdg_toplevel_set_title(state.toplevel, "Futura Terminal");
    wl_surface_commit(state.surface);

    /* Wait for configure */
    while (!state.configured) {
        wl_display_roundtrip(state.display);
    }
    xdg_surface_ack_configure(state.xdg_surface, state.configure_serial);

    /* Create shared memory buffer */
    state.shm_size = (size_t)TERM_WIDTH * TERM_HEIGHT * 4u;
    const char shm_name[] = "/wl-term-shm";
    state.shm_fd = fut_shm_create(shm_name, state.shm_size, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (state.shm_fd < 0) {
        printf("[WL-TERM] Failed to create shm\n");
        wl_display_disconnect(state.display);
        return -1;
    }

    state.shm_data = (void *)sys_mmap(NULL, (long)state.shm_size,
                                      PROT_READ | PROT_WRITE, MAP_SHARED,
                                      state.shm_fd, 0);
    if ((long)state.shm_data < 0) {
        printf("[WL-TERM] mmap failed\n");
        sys_close(state.shm_fd);
        wl_display_disconnect(state.display);
        return -1;
    }

    struct wl_shm_pool *pool = wl_shm_create_pool(state.shm, state.shm_fd,
                                                   (int32_t)state.shm_size);
    state.buffer = wl_shm_pool_create_buffer(pool, 0, TERM_WIDTH, TERM_HEIGHT,
                                             TERM_WIDTH * 4, WL_SHM_FORMAT_ARGB8888);
    wl_shm_pool_destroy(pool);

    /* Spawn shell process */
    if (spawn_shell(&state.term) < 0) {
        printf("[WL-TERM] Failed to spawn shell\n");
        sys_munmap_call(state.shm_data, (long)state.shm_size);
        sys_close(state.shm_fd);
        wl_display_disconnect(state.display);
        return -1;
    }

    /* Initial draw */
    redraw(&state);

    /* Main event loop */
    while (state.running) {
        if (!main_loop_iteration(&state)) {
            break;
        }

        /* Small delay to avoid busy-wait */
        struct fut_timespec ts = { .tv_sec = 0, .tv_nsec = 10000000 };  /* 10ms */
        sys_nanosleep_call(&ts, NULL);
    }

    /* Cleanup */
    printf("[WL-TERM] Shutting down\n");

    if (state.term.shell_stdin_fd >= 0) {
        sys_close(state.term.shell_stdin_fd);
    }
    if (state.term.shell_stdout_fd >= 0) {
        sys_close(state.term.shell_stdout_fd);
    }

    if (state.frame_cb) {
        wl_callback_destroy(state.frame_cb);
    }
    if (state.buffer) {
        wl_buffer_destroy(state.buffer);
    }
    if (state.shm_data) {
        sys_munmap_call(state.shm_data, (long)state.shm_size);
    }
    if (state.shm_fd >= 0) {
        sys_close(state.shm_fd);
        fut_shm_unlink(shm_name);
    }

    if (state.keyboard) {
        wl_keyboard_destroy(state.keyboard);
    }
    if (state.seat) {
        wl_seat_destroy(state.seat);
    }
    if (state.toplevel) {
        xdg_toplevel_destroy(state.toplevel);
    }
    if (state.xdg_surface) {
        xdg_surface_destroy(state.xdg_surface);
    }
    if (state.surface) {
        wl_surface_destroy(state.surface);
    }
    if (state.xdg_wm_base) {
        xdg_wm_base_destroy(state.xdg_wm_base);
    }
    wl_display_disconnect(state.display);

    return 0;
}
